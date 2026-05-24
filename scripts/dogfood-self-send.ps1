#Requires -Version 5.1
<#
.SYNOPSIS
  Dogfood drill: send a small amount from a testnet wallet to itself, end-to-end.

.DESCRIPTION
  Pre-mainnet dogfood drill. Unlike smoke-test-tx.ps1 (which creates fresh
  wallets each run), this exercises the real wallet path against the user's
  long-lived testnet wallet. Runs:

    1. wallet address  -> parse spend / view public keys from stdout
    2. Print plan + confirm Y/N before sending
    3. wallet send --to-spend ... --to-view ... --amount ...
    4. Append one-line audit row to out\dogfood-self-send-log.csv

  Exits 0 on success, 1 on any failure (cancelled prompt, RPC error,
  parse failure, etc).

.PARAMETER WalletPath
  Path to the wallet file. Required (no default, since this drill touches
  a real wallet and an accidental default would be hazardous).

.PARAMETER Amount
  Atomic units to send. Default 1_000_000_000 = 0.001 tCYNC.
  (1 tCYNC = 10^12 atomic units.)

.PARAMETER Node
  RPC endpoint. Default: Cloudflare-fronted public testnet API.

.PARAMETER Network
  Network name. Default testnet.

.PARAMETER NonInteractive
  Skip the Y/N confirmation prompt. Use only in scripted runs where
  the caller has already verified intent (e.g., a scheduled drill).

.EXAMPLE
  .\scripts\dogfood-self-send.ps1 -WalletPath C:\wallets\testnet.bin

.EXAMPLE
  .\scripts\dogfood-self-send.ps1 -WalletPath C:\wallets\testnet.bin -Amount 10000000000
  # 0.01 tCYNC
#>

param(
  [Parameter(Mandatory=$true)][string]$WalletPath,
  [uint64]$Amount = 1000000000,
  [string]$Node = 'https://api.coincync.network/rpc/testnet',
  [string]$Network = 'testnet',
  [switch]$NonInteractive,
  # Windows Credential Manager target to read the wallet password from.
  # Create once with:
  #   New-StoredCredential -Target 'coincync-testnet-wallet' \
  #     -UserName 'wallet' -Password '<pw>' -Persist LocalMachine
  # Requires the CredentialManager PowerShell module. If the credential
  # isn't found, the script falls back to Read-Host (interactive runs only).
  [string]$CredentialTarget = 'coincync-testnet-wallet'
)

$ErrorActionPreference = 'Stop'

# --locate binary --------------------------------------------------
$RepoRoot  = Split-Path -Parent $PSScriptRoot
$WalletBin = Join-Path $RepoRoot 'target\release\coincync-wallet.exe'

if (-not (Test-Path $WalletBin)) {
  Write-Host "FAIL: wallet binary not found at $WalletBin" -ForegroundColor Red
  Write-Host "Run: cargo build --release --workspace" -ForegroundColor Yellow
  exit 1
}
if (-not (Test-Path $WalletPath)) {
  Write-Host "FAIL: wallet file not found at $WalletPath" -ForegroundColor Red
  exit 1
}

# --resolve password: Credential Manager -> fallback to Read-Host ---
# Preferred: OS-level keyring via the CredentialManager module (encrypted
# at rest, scoped to your user, no plaintext on disk, no argv exposure).
# Fallback: interactive Read-Host SecureString - used when no credential
# entry exists. -NonInteractive forbids the fallback (so a scheduled run
# that loses the keyring entry fails loudly rather than hanging).
# We pass the password to the wallet binary via `--password -` on stdin
# (supported by the wallet's resolve_password helper in src/bin/wallet.rs).
# stdin is invisible to peer processes (unlike argv) AND not inherited by
# children (unlike env vars), so exposure is minimised on both vectors.
$securePw = $null
$credModule = Get-Module -ListAvailable -Name CredentialManager | Select-Object -First 1
if ($credModule) {
  try {
    Import-Module CredentialManager -ErrorAction Stop
    $cred = Get-StoredCredential -Target $CredentialTarget -ErrorAction Stop
    if ($cred -and $cred.Password) { $securePw = $cred.Password }
  } catch {
    # No matching entry, or module load failed - fall through to prompt.
  }
}
if (-not $securePw) {
  if ($NonInteractive) {
    Write-Host "FAIL: -NonInteractive but no credential at target '$CredentialTarget'" -ForegroundColor Red
    Write-Host "Create with: New-StoredCredential -Target '$CredentialTarget' -UserName 'wallet' -Password '<pw>' -Persist LocalMachine" -ForegroundColor Yellow
    exit 1
  }
  $securePw = Read-Host -Prompt "Wallet password" -AsSecureString
}
$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePw)
$plainPw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) | Out-Null

# --1. wallet address -> extract spend/view hex keys ----------------
Write-Host ''
Write-Host 'Resolving wallet address...' -ForegroundColor Cyan
$addrArgs = @(
  '--network', $Network,
  '--wallet',  $WalletPath,
  'address',
  '--password', '-'
)
$addrOut = $plainPw | & $WalletBin @addrArgs 2>&1
if ($LASTEXITCODE -ne 0) {
  $plainPw = $null
  Write-Host "FAIL: wallet address exited $LASTEXITCODE" -ForegroundColor Red
  Write-Host $addrOut
  exit 1
}

# Parse the three "Field: value" lines the wallet prints.
$address    = ($addrOut | Select-String -Pattern '^Address:\s+(.+)$').Matches.Groups[1].Value
$spendHex   = ($addrOut | Select-String -Pattern '^Spend public:\s+([0-9a-f]+)$').Matches.Groups[1].Value
$viewHex    = ($addrOut | Select-String -Pattern '^View public:\s+([0-9a-f]+)$').Matches.Groups[1].Value

if (-not $spendHex -or -not $viewHex) {
  $plainPw = $null
  Write-Host 'FAIL: could not parse spend/view keys from `wallet address` output:' -ForegroundColor Red
  Write-Host $addrOut
  exit 1
}

# --2. show plan + confirm -----------------------------------------
$cyncAmount = [decimal]$Amount / 1000000000000.0
Write-Host ''
Write-Host '--------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '   CoinCync testnet dogfood - self-send drill'           -ForegroundColor Cyan
Write-Host '--------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ("  wallet:    $WalletPath")
Write-Host ("  address:   $address")
Write-Host ("  amount:    $Amount atomic ($cyncAmount tCYNC)")
Write-Host ("  rpc node:  $Node")
Write-Host ''

if (-not $NonInteractive) {
  $confirm = Read-Host 'Send? (y/N)'
  if ($confirm -notmatch '^[Yy]') {
    $plainPw = $null
    Write-Host 'Cancelled.' -ForegroundColor Yellow
    exit 1
  }
}

# --3. wallet send --------------------------------------------------
Write-Host ''
Write-Host 'Sending...' -ForegroundColor Cyan
$sendArgs = @(
  '--network', $Network,
  '--wallet',  $WalletPath,
  '--node',    $Node,
  'send',
  '--password', '-',
  '--to-spend', $spendHex,
  '--to-view',  $viewHex,
  '--amount',   $Amount.ToString()
)
$sendOut = $plainPw | & $WalletBin @sendArgs 2>&1
$sendExit = $LASTEXITCODE

# Zero the plaintext password as soon as both wallet calls are done.
$plainPw = $null

Write-Host $sendOut
if ($sendExit -ne 0) {
  Write-Host "FAIL: wallet send exited $sendExit" -ForegroundColor Red
  exit 1
}

# Gate audit logging on the actual mempool-acceptance line from cmd_send
# (src/bin/wallet.rs:1215), not just exit code. A bug that exits 0 without
# submitting wouldn't get falsely logged as a successful send.
$accepted = $sendOut | Select-String -Pattern 'OK:\s+tx\s+accepted\s+by\s+mempool' -Quiet
if (-not $accepted) {
  Write-Host "FAIL: wallet send exited 0 but no 'tx accepted by mempool' line in output" -ForegroundColor Red
  exit 1
}

# txid from the "  Hash:    <hex>" line printed by cmd_send at src/bin/wallet.rs:1152.
$txid = ($sendOut | Select-String -Pattern '^\s*Hash:\s+([0-9a-f]+)\s*$' | Select-Object -First 1).Matches.Groups[1].Value
if (-not $txid) { $txid = 'unknown' }

# --4. audit-trail log ---------------------------------------------
$outDir = Join-Path $RepoRoot 'out'
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir | Out-Null }
$logPath = Join-Path $outDir 'dogfood-self-send-log.csv'
if (-not (Test-Path $logPath)) {
  'timestamp_utc,wallet,address,amount_atomic,txid,node' | Out-File -FilePath $logPath -Encoding utf8
}
$ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
"$ts,$WalletPath,$address,$Amount,$txid,$Node" | Add-Content -Path $logPath -Encoding utf8

Write-Host ''
Write-Host "PASS - txid: $txid" -ForegroundColor Green
Write-Host "Logged to: $logPath" -ForegroundColor DarkGray
exit 0
