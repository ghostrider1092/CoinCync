#Requires -Version 5.1
<#
.SYNOPSIS
  Register a Windows Scheduled Task that runs dogfood-self-send.ps1
  on a recurring interval, generating real testnet TX activity for
  listing-application metrics and chain-functionality dogfooding.

.DESCRIPTION
  Pre-mainnet, listing committees (Kraken / Bitfinex / MEXC) want to
  see that the testnet runs at non-trivial volume -- empty blocks
  read as "the chain technically works but nobody uses it." A
  recurring self-send drill solves three problems at once:

    1. Generates citable TX volume (5,760 TXs over 4 months at 30 min
       cadence). Listing applications can quote "X testnet TXs since
       genesis on Y date" as the demand signal.
    2. Exercises the wallet end-to-end every 30 min, so any release
       regression that breaks 'wallet send' surfaces within an hour.
    3. Keeps the mempool occupied with real privacy-stack traffic,
       which is good soak input.

  Idempotent: re-running this script with the same TaskName updates
  the existing task in place rather than duplicating.

  To pause the drill (without uninstalling):
    Disable-ScheduledTask -TaskName 'CoinCync-Dogfood-Self-Send'

  To resume:
    Enable-ScheduledTask -TaskName 'CoinCync-Dogfood-Self-Send'

  To uninstall completely:
    Unregister-ScheduledTask -TaskName 'CoinCync-Dogfood-Self-Send' -Confirm:$false

.PARAMETER WalletPath
  Absolute path to the testnet wallet file the drill will use.
  This wallet MUST be funded (recommend >= 10 tCYNC starting balance
  to survive 4 months of self-send fees at default amount). Either
  mine directly to it or transfer from the faucet.

.PARAMETER Amount
  Atomic units sent per drill. Default 1_000_000_000 (0.001 tCYNC).
  Self-sends return principal minus fees, so the wallet drains at
  approximately the per-tx fee rate.

.PARAMETER IntervalMinutes
  Minutes between drills. Default 30. Lower = more TX volume but
  more fee drain on the source wallet. Higher = less compelling
  listing-application metric.

.PARAMETER TaskName
  Scheduled Task name. Default 'CoinCync-Dogfood-Self-Send'.

.PARAMETER CredentialTarget
  Windows Credential Manager target storing the wallet password.
  Default 'coincync-testnet-wallet'. Must exist before registration
  (the task runs -NonInteractive and will fail if no credential).

.EXAMPLE
  .\scripts\install-dogfood-schedule.ps1 -WalletPath C:\wallets\testnet-dogfood.bin
  # Default 30 min interval, default amount, default task name.

.EXAMPLE
  .\scripts\install-dogfood-schedule.ps1 -WalletPath C:\wallets\testnet-dogfood.bin -IntervalMinutes 60
  # Hourly cadence (lower fee drain).

.NOTES
  ONE-TIME SETUP before running this:

    1. Build the wallet binary:
         cargo build --release --workspace

    2. Install the CredentialManager PowerShell module (admin):
         Install-Module -Name CredentialManager -Scope AllUsers

    3. Store the wallet password in Credential Manager:
         New-StoredCredential -Target 'coincync-testnet-wallet' `
             -UserName 'wallet' -Password '<password>' -Persist LocalMachine

    4. Fund the wallet (>= 10 tCYNC). Either mine to it or use the
       project faucet.

    5. Run this script to register the schedule.

  The scheduled task runs as the current user (NOT SYSTEM) so that
  the Credential Manager entry is accessible. Logging from each run
  appends to out\dogfood-self-send-log.csv per the underlying script.
#>

param(
  [Parameter(Mandatory=$true)][string]$WalletPath,
  [uint64]$Amount = 1000000000,
  [int]$IntervalMinutes = 30,
  [string]$TaskName = 'CoinCync-Dogfood-Self-Send',
  [string]$CredentialTarget = 'coincync-testnet-wallet'
)

$ErrorActionPreference = 'Stop'

# --- Sanity checks ---------------------------------------------------
$RepoRoot     = Split-Path -Parent $PSScriptRoot
$WalletBin    = Join-Path $RepoRoot 'target\release\coincync-wallet.exe'
$DogfoodPs1   = Join-Path $PSScriptRoot 'dogfood-self-send.ps1'
$LogDir       = Join-Path $RepoRoot 'out'

if (-not (Test-Path $WalletBin)) {
  Write-Host "FAIL: wallet binary not found at $WalletBin" -ForegroundColor Red
  Write-Host "      Build with: cargo build --release --workspace" -ForegroundColor Yellow
  exit 1
}
if (-not (Test-Path $WalletPath)) {
  Write-Host "FAIL: wallet file not found at $WalletPath" -ForegroundColor Red
  exit 1
}
if (-not (Test-Path $DogfoodPs1)) {
  Write-Host "FAIL: dogfood script not found at $DogfoodPs1" -ForegroundColor Red
  exit 1
}
if ($IntervalMinutes -lt 5) {
  Write-Host "FAIL: IntervalMinutes=$IntervalMinutes is too aggressive. Min 5." -ForegroundColor Red
  exit 1
}

# Verify Credential Manager entry exists. The scheduled task runs
# -NonInteractive and will fail at 03:00 on a Tuesday if missing,
# so catch it here with a clear error message instead.
$credModule = Get-Module -ListAvailable -Name CredentialManager | Select-Object -First 1
if (-not $credModule) {
  Write-Host "FAIL: CredentialManager module not installed" -ForegroundColor Red
  Write-Host "      Install with: Install-Module -Name CredentialManager -Scope AllUsers" -ForegroundColor Yellow
  exit 1
}
try {
  Import-Module CredentialManager -ErrorAction Stop
  $cred = Get-StoredCredential -Target $CredentialTarget -ErrorAction Stop
  if (-not $cred -or -not $cred.Password) { throw "no entry" }
} catch {
  Write-Host "FAIL: no Credential Manager entry at target '$CredentialTarget'" -ForegroundColor Red
  Write-Host "      Create with:" -ForegroundColor Yellow
  Write-Host "      New-StoredCredential -Target '$CredentialTarget' -UserName 'wallet' -Password '<pw>' -Persist LocalMachine" -ForegroundColor Yellow
  exit 1
}

# --- Build the scheduled-task definition ----------------------------
# Task Scheduler swallows console output by default; pipe everything
# to a rolling log so we can diagnose any failed run. The structured
# audit trail still lives in out\dogfood-self-send-log.csv (written
# by dogfood-self-send.ps1 itself).
$RunLog = Join-Path $LogDir 'dogfood-scheduled-run.log'
if (-not (Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir | Out-Null }

$psExe = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$action = New-ScheduledTaskAction `
  -Execute $psExe `
  -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$DogfoodPs1`" -WalletPath `"$WalletPath`" -Amount $Amount -NonInteractive -CredentialTarget `"$CredentialTarget`" *>> `"$RunLog`""

# Trigger: every $IntervalMinutes minutes, first run ~1 min from now
# so the operator can confirm the schedule works without waiting a
# full interval.
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
            -RepetitionInterval (New-TimeSpan -Minutes $IntervalMinutes)

# Settings: kill any run exceeding 10 min (hung RPC = locked wallet
# file = next run can't start anyway). Single-instance only -- if a
# run is still going when the next trigger fires, skip it rather
# than queue.
$settings = New-ScheduledTaskSettingsSet `
  -AllowStartIfOnBatteries `
  -DontStopIfGoingOnBatteries `
  -StartWhenAvailable `
  -MultipleInstances IgnoreNew `
  -ExecutionTimeLimit (New-TimeSpan -Minutes 10)

# Run as current user so the per-user Credential Manager entry is
# accessible. SYSTEM cannot read user credentials.
$principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive

# --- Register (idempotent) -----------------------------------------
$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($existing) {
  Write-Host "Updating existing scheduled task '$TaskName'..." -ForegroundColor Cyan
  Set-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
} else {
  Write-Host "Registering new scheduled task '$TaskName'..." -ForegroundColor Cyan
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Description "CoinCync testnet dogfood self-send drill ($IntervalMinutes min cadence)" | Out-Null
}

# --- Summary --------------------------------------------------------
Write-Host ''
Write-Host '====================================================================' -ForegroundColor DarkGray
Write-Host "  Scheduled task '$TaskName' registered" -ForegroundColor Green
Write-Host '====================================================================' -ForegroundColor DarkGray
Write-Host "  wallet:       $WalletPath"
Write-Host "  amount:       $Amount atomic ($([decimal]$Amount / 1000000000000.0) tCYNC) per drill"
Write-Host "  cadence:      every $IntervalMinutes minutes"
Write-Host "  first run:    ~$((Get-Date).AddMinutes(1).ToString('HH:mm:ss')) (about 1 min from now)"
Write-Host "  TXs per day:  ~$([math]::Round(1440 / $IntervalMinutes))"
Write-Host "  TXs per 4mo:  ~$([math]::Round(1440 / $IntervalMinutes * 30 * 4))"
Write-Host ''
Write-Host "  CSV audit:    out\dogfood-self-send-log.csv"
Write-Host "  Run-log tail: $RunLog"
Write-Host ''
Write-Host 'Commands:'
Write-Host "  Status:  Get-ScheduledTask -TaskName '$TaskName' | Get-ScheduledTaskInfo"
Write-Host "  Pause:   Disable-ScheduledTask -TaskName '$TaskName'"
Write-Host "  Resume:  Enable-ScheduledTask  -TaskName '$TaskName'"
Write-Host "  Remove:  Unregister-ScheduledTask -TaskName '$TaskName' -Confirm:`$false"
Write-Host ''
