# CoinCync — easy launcher.
# Double-click Start-CoinCync.cmd (which runs this), pick a number, done.
# Brings a node up on the public testnet, with one-key options to mine or make
# a wallet. No flags to remember.

$ErrorActionPreference = 'Stop'

# ---- settings (sensible defaults; edit if you know what you're doing) --------
$Network = 'testnet'
$Seed    = '2.29.34.197:28080'          # public testnet seed peer
$DataDir = Join-Path $env:USERPROFILE '.coincync'
$Wallet  = Join-Path $env:USERPROFILE '.coincync\wallets\default.wallet'

# The easy launcher uses an UNENCRYPTED wallet so nothing ever asks for a
# password. (If you created an encrypted wallet yourself, remove this line and
# you'll be prompted instead.)
$env:COINCYNC_WALLET_PASSWORD = ''

# ---- find the binaries -------------------------------------------------------
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$roots = @(
    $here,
    (Join-Path $here '..'),
    (Join-Path $here '..\target\release'),
    (Join-Path $here '..\target\debug')
)
function Find-Exe($name) {
    foreach ($r in $roots) {
        $p = Join-Path $r "$name.exe"
        if (Test-Path $p) { return (Resolve-Path $p).Path }
    }
    $cmd = Get-Command "$name.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}
$Node   = Find-Exe 'coincync-node'
$WalletExe = Find-Exe 'coincync-wallet'

function Banner {
    Clear-Host
    Write-Host ''
    Write-Host '   ====================================================' -ForegroundColor Cyan
    Write-Host '      CoinCync  -  easy launcher' -ForegroundColor Cyan
    Write-Host '   ====================================================' -ForegroundColor Cyan
    Write-Host ("      network : {0}" -f $Network)
    Write-Host ("      node    : {0}" -f ($(if ($Node) { 'found' } else { 'NOT FOUND' })))
    Write-Host ("      data    : {0}" -f $DataDir)
    Write-Host ''
}

function Ensure-Node {
    if (-not $Node) {
        Write-Host 'Could not find coincync-node.exe.' -ForegroundColor Red
        Write-Host 'Put this launcher next to coincync-node.exe (or build it first), then retry.'
        Read-Host 'Press Enter'
        return $false
    }
    return $true
}

function Get-MiningAddress {
    if (-not $WalletExe) {
        Write-Host 'coincync-wallet.exe not found - cannot make a mining address.' -ForegroundColor Red
        return $null
    }
    if (-not (Test-Path $Wallet)) {
        Write-Host 'No wallet yet - creating one (unencrypted, for easy mining)...' -ForegroundColor Yellow
        & $WalletExe --wallet $Wallet --network $Network create --no-encrypt | Out-Host
    }
    # Ask the wallet for its address (JSON, so we can parse it reliably).
    $out = & $WalletExe --wallet $Wallet --network $Network address --json 2>$null | Out-String
    $addr = $null
    try { $addr = ($out | ConvertFrom-Json).address } catch {}
    if (-not $addr) {
        # Fall back to the plain-text "Address: ..." line.
        $line = (& $WalletExe --wallet $Wallet --network $Network address 2>$null | Select-String 'Address').ToString()
        if ($line) { $addr = ($line -split '\s+')[-1] }
    }
    return $addr
}

function Run-Node([string]$mineAddr) {
    $args = @('--network', $Network, '--data-dir', $DataDir, '--addnode', $Seed)
    if ($mineAddr) { $args += @('--mine', $mineAddr) }
    Banner
    if ($mineAddr) {
        Write-Host ("Mining to: {0}" -f $mineAddr) -ForegroundColor Green
    }
    Write-Host 'Starting the node. It will connect to the network and sync.' -ForegroundColor Green
    Write-Host 'Leave this window open. Press Ctrl+C to stop.' -ForegroundColor DarkGray
    Write-Host ''
    & $Node @args
    Write-Host ''
    Read-Host 'Node stopped. Press Enter to return to the menu'
}

# ---- menu loop ---------------------------------------------------------------
$run = $true
while ($run) {
    Banner
    Write-Host '   What would you like to do?' -ForegroundColor White
    Write-Host ''
    Write-Host '     [1]  Run a node   (join the network)'
    Write-Host '     [2]  Run a node AND mine   (earn CYNC)'
    Write-Host '     [3]  Create / show my wallet'
    Write-Host '     [4]  Check my balance'
    Write-Host '     [Q]  Quit'
    Write-Host ''
    $choice = (Read-Host '   Type a number and press Enter').Trim().ToUpper()

    switch ($choice) {
        '1' { if (Ensure-Node) { Run-Node $null } }
        '2' {
            if (Ensure-Node) {
                $a = Get-MiningAddress
                if ($a) { Run-Node $a } else { Read-Host 'Could not get an address. Press Enter' }
            }
        }
        '3' {
            if ($WalletExe) {
                if (-not (Test-Path $Wallet)) {
                    & $WalletExe --wallet $Wallet --network $Network create --no-encrypt | Out-Host
                }
                Write-Host ''
                & $WalletExe --wallet $Wallet --network $Network address | Out-Host
            } else { Write-Host 'coincync-wallet.exe not found.' -ForegroundColor Red }
            Read-Host 'Press Enter'
        }
        '4' {
            if ($WalletExe) {
                & $WalletExe --wallet $Wallet --network $Network balance | Out-Host
            } else { Write-Host 'coincync-wallet.exe not found.' -ForegroundColor Red }
            Read-Host 'Press Enter'
        }
        'Q' { $run = $false }
        default { }
    }
}
