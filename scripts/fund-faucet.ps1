#requires -Version 5.1
<#
.SYNOPSIS
  One-shot: send testnet CYNC from your local wallet to the public-
  testnet faucet hot wallet.

.DESCRIPTION
  Wraps `coincync-wallet send` to fund the hot wallet that the
  Rust faucet service drips from. Prompts for your wallet password
  via Read-Host -AsSecureString so the password never appears in
  shell history or environment.

  Default destination is the production faucet hot wallet on the
  api box. Default amount is 100 tCYNC = 10 drips of 10 tCYNC each.

.PARAMETER Wallet
  Path to your local wallet file. Default: ~/.coincync/wallets/default.wallet

.PARAMETER ToSpend
  Recipient spend public key (hex). Default: faucet hot wallet on api box.

.PARAMETER ToView
  Recipient view public key (hex). Default: faucet hot wallet on api box.

.PARAMETER AmountAtomic
  Amount to send, in atomic units. Default: 100 tCYNC = 100 * 10^12 atomic.

.PARAMETER Node
  Node RPC endpoint. Default: public testnet API.

.PARAMETER Password
  Wallet password as a plain string. If omitted, the script falls
  back to the CYNC_WALLET_PASSWORD env var, then to an interactive
  Read-Host -AsSecureString prompt. Use the env-var path when you
  need a non-interactive run (CI, scripted launch flow, etc.) and
  prefer to keep the password out of shell history.

.EXAMPLE
  .\scripts\fund-faucet.ps1
  # prompts for password, sends 100 tCYNC

.EXAMPLE
  $env:CYNC_WALLET_PASSWORD = 'mypassword'
  .\scripts\fund-faucet.ps1
  Remove-Item env:CYNC_WALLET_PASSWORD
  # non-interactive via env var; cleared after the run
#>

param(
  [string]$Wallet = "$env:USERPROFILE\.coincync\wallets\default.wallet",
  [string]$ToSpend = 'ee2a3729621b7106e2071bcffd89057c993f4c3aad68f4ae52668a25ef1d5f67',
  [string]$ToView  = '5aa89d015ab9badbf8c3d04701bbc58d14042960eb8455778f6ef562a3725c33',
  [long]  $AmountAtomic = 100000000000000,  # 100 tCYNC
  [string]$Node = 'https://api.coincync.network/rpc/testnet',
  [SecureString]$Password
)

$ErrorActionPreference = 'Stop'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$WalletBin = Join-Path $RepoRoot 'target\release\coincync-wallet.exe'
if (-not (Test-Path $WalletBin)) {
    Write-Host "FAIL: $WalletBin not found. Run: cargo build --release --bin coincync-wallet --features `"randomx testnet`"" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $Wallet)) {
    Write-Host "FAIL: wallet file not found at $Wallet" -ForegroundColor Red
    exit 1
}

$amountCync = $AmountAtomic / 1000000000000.0

Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '   Fund the public-testnet faucet hot wallet'                  -ForegroundColor Cyan
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ("  from wallet: $Wallet")
Write-Host ("  to spend:    $ToSpend")
Write-Host ("  to view:     $ToView")
Write-Host ("  amount:      $AmountAtomic atomic ($amountCync tCYNC)")
Write-Host ("  node:        $Node")
Write-Host ''

# Resolve the password from one of three sources, in priority order:
# 1. -Password [SecureString] parameter (typed-in or piped from user code)
# 2. $env:CYNC_WALLET_PASSWORD (non-interactive convenience for one-shot runs)
# 3. Interactive Read-Host -AsSecureString prompt
# We hold a SecureString as long as possible and only convert to plain
# text at the wallet-CLI boundary, since the binary takes --password as a
# regular string argument.
if ($Password) {
    $secure = $Password
} elseif ($env:CYNC_WALLET_PASSWORD) {
    Write-Host '  (using $env:CYNC_WALLET_PASSWORD)' -ForegroundColor DarkGray
    $secure = ConvertTo-SecureString -String $env:CYNC_WALLET_PASSWORD -AsPlainText -Force
} else {
    $secure = Read-Host -Prompt 'Wallet password' -AsSecureString
}

# Convert to plain only at the call site; clear immediately after.
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try {
    $walletPwd = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
} finally {
    [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
}

Write-Host ''
Write-Host 'Sending...' -ForegroundColor Yellow

$out = & $WalletBin `
    --network testnet `
    --wallet $Wallet `
    --node $Node `
    send `
    --password $walletPwd `
    --to-spend $ToSpend `
    --to-view $ToView `
    --amount $AmountAtomic 2>&1

# Drop the password ASAP
$walletPwd = $null

Write-Host ''
$out | Out-Host

if ($LASTEXITCODE -ne 0) {
    Write-Host ''
    Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host "  FAIL  (wallet exit $LASTEXITCODE)" -ForegroundColor Red
    Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
    exit 1
}

# Pull tx hash from output
$txHash = $null
$hashLine = $out | Select-String -Pattern '^\s*Hash:\s*([a-f0-9]{64})'
if ($hashLine) { $txHash = $hashLine.Matches[0].Groups[1].Value }

Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '  PASS  funding tx submitted'                                  -ForegroundColor Green
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
if ($txHash) {
    Write-Host "  tx hash: $txHash"
    Write-Host "  watch:   https://explorer.coincync.network/?p=tx&q=$txHash"
}
Write-Host ''
Write-Host '  Wait ~2-5 min for the funding tx to confirm in the hot wallet,'
Write-Host '  then test the faucet end-to-end:'
Write-Host '    .\scripts\smoke-test-faucet.ps1'
exit 0
