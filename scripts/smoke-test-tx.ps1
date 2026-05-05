#Requires -Version 5.1
<#
.SYNOPSIS
  End-to-end smoke test: create two wallets, mine to A, send to B, verify receipt.

.DESCRIPTION
  Exercises the full user-facing transaction path against the public testnet.
  The 72h soak only samples RPC health — it tells us nothing about whether a
  user can actually send and receive coins. This script closes that gap.

  Pipeline:
    1. Create fresh wallet A (sender) and wallet B (recipient)
    2. Extract their addresses + (spend, view) public keys
    3. Spawn coincync-rig pointed at wallet A's address; mine until A has
       a confirmed block reward
    4. Stop the rig; scan wallet A so it sees the coinbase output
    5. Send a small amount from A to B
    6. Scan wallet B; verify the amount arrives
    7. Cleanup

  PASS / FAIL reported with exit code 0 / 1.

.PARAMETER Node
  RPC endpoint. Defaults to the Cloudflare-fronted public testnet API.

.PARAMETER Network
  Network name (testnet / regtest). Default testnet.

.PARAMETER Threads
  Mining threads to spin up. Default 4.

.PARAMETER FundTimeoutMinutes
  Max wait for wallet A to receive a block reward. Default 10.

.PARAMETER ConfirmTimeoutMinutes
  Max wait for the send tx to confirm + appear in B's scan. Default 5.

.PARAMETER KeepArtifacts
  If set, the temp wallet files are kept after the run for debugging.
  Default: cleanup on success, keep on failure.

.EXAMPLE
  pwsh scripts\smoke-test-tx.ps1
#>

param(
  [string]$Node = 'https://api.coincync.network/rpc/testnet',
  [string]$Network = 'testnet',
  [int]$Threads = 4,
  [int]$FundTimeoutMinutes = 10,
  [int]$ConfirmTimeoutMinutes = 5,
  [switch]$KeepArtifacts
)

$ErrorActionPreference = 'Stop'

# ── locate binaries ─────────────────────────────────────────────────
$RepoRoot = Split-Path -Parent $PSScriptRoot
$WalletBin = Join-Path $RepoRoot 'target\release\coincync-wallet.exe'
$RigBin    = Join-Path $RepoRoot 'target\release\coincync-rig.exe'

foreach ($b in @($WalletBin, $RigBin)) {
  if (-not (Test-Path $b)) {
    Write-Host "FAIL: binary not found at $b" -ForegroundColor Red
    Write-Host "Run: cargo build --release --workspace" -ForegroundColor Yellow
    exit 1
  }
}

# ── temp dir for this run ───────────────────────────────────────────
$ts        = Get-Date -Format 'yyyyMMdd-HHmmss'
$tmpDir    = Join-Path $env:TEMP "coincync-smoketest-$ts"
New-Item -ItemType Directory -Force -Path $tmpDir | Out-Null
$walletA   = Join-Path $tmpDir 'walletA.bin'
$walletB   = Join-Path $tmpDir 'walletB.bin'
$logA      = Join-Path $tmpDir 'walletA.log'
$logB      = Join-Path $tmpDir 'walletB.log'
$rigLog    = Join-Path $tmpDir 'rig.log'
$pwd       = 'smoketest-do-not-reuse-this-password'

# Header
Write-Host ''
Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray
Write-Host '   CoinCync smoke test — wallet → mine → send → verify'   -ForegroundColor Cyan
Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray
Write-Host ("  workspace: $tmpDir")
Write-Host ("  rpc node:  $Node")
Write-Host ("  network:   $Network")
Write-Host ''

$failure = $null

# ── helper: invoke wallet binary, capture output to a file too ──────
function Invoke-Wallet {
  param([string]$Wallet, [Parameter(ValueFromRemainingArguments)][string[]]$Rest)
  $args = @(
    '--network', $Network,
    '--wallet', $Wallet,
    '--node', $Node
  ) + $Rest
  & $WalletBin @args 2>&1
}

# ── helper: parse "Field: value" lines from wallet output ───────────
function Parse-Field {
  param([string[]]$Output, [string]$Label)
  $hit = $Output | Select-String -Pattern "^\s*${Label}:\s*(.+)$"
  if ($hit) { return $hit.Matches[0].Groups[1].Value.Trim() }
  return $null
}

# ── stage 1: create both wallets ────────────────────────────────────
try {
  Write-Host '[1/7] creating wallets…' -ForegroundColor Yellow
  Invoke-Wallet $walletA create --password $pwd --force | Tee-Object -FilePath $logA | Out-Null
  Invoke-Wallet $walletB create --password $pwd --force | Tee-Object -FilePath $logB | Out-Null
  Write-Host '      wallet A: ' -NoNewline; Write-Host $walletA -ForegroundColor DarkGray
  Write-Host '      wallet B: ' -NoNewline; Write-Host $walletB -ForegroundColor DarkGray
} catch {
  $failure = "wallet create failed: $_"
}

# ── stage 2: get addresses + pubkeys ────────────────────────────────
$aAddr = $aSpend = $aView = $null
$bAddr = $bSpend = $bView = $null

if (-not $failure) {
  try {
    Write-Host '[2/7] reading addresses…' -ForegroundColor Yellow
    $aOut = Invoke-Wallet $walletA address --password $pwd
    $bOut = Invoke-Wallet $walletB address --password $pwd
    $aAddr  = Parse-Field $aOut 'Address'
    $aSpend = Parse-Field $aOut 'Spend public'
    $aView  = Parse-Field $aOut 'View public'
    $bAddr  = Parse-Field $bOut 'Address'
    $bSpend = Parse-Field $bOut 'Spend public'
    $bView  = Parse-Field $bOut 'View public'
    if (-not ($aAddr -and $aSpend -and $aView -and $bAddr -and $bSpend -and $bView)) {
      throw 'failed to parse Address / Spend public / View public from wallet output'
    }
    Write-Host '      A address: ' -NoNewline; Write-Host ($aAddr.Substring(0,32) + '…') -ForegroundColor DarkGray
    Write-Host '      B address: ' -NoNewline; Write-Host ($bAddr.Substring(0,32) + '…') -ForegroundColor DarkGray
  } catch {
    $failure = "address read failed: $_"
  }
}

# ── stage 3: mine to wallet A until balance > 0 ─────────────────────
$rig = $null
if (-not $failure) {
  try {
    Write-Host "[3/7] spawning rig (mining to A's address, $Threads threads)…" -ForegroundColor Yellow
    $rigArgs = @(
      'run-solo',
      '--node', $Node,
      '--address', $aAddr,
      '--threads', "$Threads",
      '--network', $Network,
      '--poll-interval-secs', '60'
    )
    $rig = Start-Process -FilePath $RigBin -ArgumentList $rigArgs `
                          -RedirectStandardOutput $rigLog `
                          -RedirectStandardError "$rigLog.err" `
                          -PassThru -WindowStyle Hidden

    $deadline = (Get-Date).AddMinutes($FundTimeoutMinutes)
    $funded = $false
    Write-Host "      waiting up to $FundTimeoutMinutes min for first block to A…" -ForegroundColor DarkGray
    while (-not $funded -and (Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 30
      try {
        Invoke-Wallet $walletA scan --password $pwd | Out-Null
        $balOut = Invoke-Wallet $walletA balance --password $pwd
        $bal = Parse-Field $balOut 'Balance total'
        if ($bal -match '(\d+)') {
          $balN = [int64]$Matches[1]
          if ($balN -gt 0) {
            Write-Host "      ✓ wallet A funded: $balN atomic units" -ForegroundColor Green
            $funded = $true
            break
          }
        }
        $remaining = [int]([math]::Round(($deadline - (Get-Date)).TotalSeconds))
        Write-Host "      still waiting… ${remaining}s left" -ForegroundColor DarkGray
      } catch {
        Write-Host "      scan/balance error (continuing): $_" -ForegroundColor DarkYellow
      }
    }
    if (-not $funded) { throw "wallet A did not receive a block reward within $FundTimeoutMinutes minutes" }
  } catch {
    $failure = "funding failed: $_"
  }
}

# ── stage 4: stop rig ───────────────────────────────────────────────
if ($rig -and -not $rig.HasExited) {
  try {
    Write-Host '[4/7] stopping rig…' -ForegroundColor Yellow
    Stop-Process -Id $rig.Id -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
  } catch {
    Write-Host "      (rig stop hiccup, continuing): $_" -ForegroundColor DarkYellow
  }
}

# ── stage 5: send A → B ─────────────────────────────────────────────
# 100,000,000 atomic units = 0.0001 CYNC. Tiny on purpose; the test only
# proves the path works, not that we can move large amounts.
$sendAmount = 100000000
if (-not $failure) {
  try {
    Write-Host "[5/7] sending $sendAmount atomic CYNC from A → B…" -ForegroundColor Yellow
    $sendOut = Invoke-Wallet $walletA send `
      --password $pwd `
      --to-spend $bSpend `
      --to-view $bView `
      --amount $sendAmount
    $sendOut | Out-File -Append -FilePath $logA -Encoding utf8
    if ($sendOut -match 'failed|error|reject') {
      throw "send command output looks like an error: $sendOut"
    }
    Write-Host "      ✓ broadcast accepted (parse output for txid)" -ForegroundColor Green
  } catch {
    $failure = "send failed: $_"
  }
}

# ── stage 6: scan B until amount visible ────────────────────────────
if (-not $failure) {
  try {
    Write-Host "[6/7] waiting up to $ConfirmTimeoutMinutes min for B to receive…" -ForegroundColor Yellow
    $deadline = (Get-Date).AddMinutes($ConfirmTimeoutMinutes)
    $received = $false
    while (-not $received -and (Get-Date) -lt $deadline) {
      Start-Sleep -Seconds 20
      try {
        Invoke-Wallet $walletB scan --password $pwd | Out-Null
        $bBalOut = Invoke-Wallet $walletB balance --password $pwd
        $bBal = Parse-Field $bBalOut 'Balance total'
        if ($bBal -match '(\d+)') {
          $bBalN = [int64]$Matches[1]
          if ($bBalN -ge $sendAmount) {
            Write-Host "      ✓ B received $bBalN atomic units (>= $sendAmount expected)" -ForegroundColor Green
            $received = $true
            break
          }
          $remaining = [int]([math]::Round(($deadline - (Get-Date)).TotalSeconds))
          Write-Host "      B balance $bBalN, waiting… ${remaining}s left" -ForegroundColor DarkGray
        }
      } catch {
        Write-Host "      scan error (continuing): $_" -ForegroundColor DarkYellow
      }
    }
    if (-not $received) { throw "wallet B did not receive funds within $ConfirmTimeoutMinutes minutes" }
  } catch {
    $failure = "receive verify failed: $_"
  }
}

# ── stage 7: report + cleanup ───────────────────────────────────────
Write-Host ''
if ($failure) {
  Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray
  Write-Host '  FAIL' -ForegroundColor Red -NoNewline
  Write-Host "  $failure"
  Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray
  Write-Host ("  artifacts kept for debugging: $tmpDir") -ForegroundColor DarkGray
  if ($rig -and -not $rig.HasExited) {
    Stop-Process -Id $rig.Id -Force -ErrorAction SilentlyContinue
  }
  exit 1
} else {
  Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray
  Write-Host '  PASS' -ForegroundColor Green -NoNewline
  Write-Host '  end-to-end transaction path is healthy.'
  Write-Host '────────────────────────────────────────────────────────' -ForegroundColor DarkGray
  if (-not $KeepArtifacts) {
    Remove-Item -Recurse -Force $tmpDir -ErrorAction SilentlyContinue
    Write-Host '  workspace cleaned up.' -ForegroundColor DarkGray
  } else {
    Write-Host ("  workspace kept: $tmpDir") -ForegroundColor DarkGray
  }
  exit 0
}
