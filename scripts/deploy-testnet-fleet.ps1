#requires -Version 5.1
<#
.SYNOPSIS
  Deploy coincync-node to a fleet of boxes and cross-wire them into a mesh so
  every node sees >=3 peers - which clears the rig's mining gate
  (crates/coincync-rig/src/orchestrator.rs:279 requires peers >= 3).

.DESCRIPTION
  For each IP in -Nodes: pushes the Linux coincync-node binary, generates a
  systemd unit whose --addnode list is *the other nodes in the fleet* plus the
  public seed, opens P2P (28080) in ufw, and starts the service. RPC stays on
  loopback (no auth/exposure needed - a co-located rig reaches it locally).

  Idempotent: re-running updates the binary + unit and restarts in place.

  MESH MATH: in a full mesh of N nodes each node sees N-1 peers, so you need
  N >= 4 for every node to reach the >=3 gate. With 3 nodes each sees only 2
  (the seed *might* add a 3rd, but it's flaky) - so 4+ is strongly recommended.

  Pre-reqs:
    1. SSH key at -KeyPath (default ~/.ssh/coincync_fleet), root on every box.
    2. Linux binary at target/release/coincync-node - build in WSL:
       wsl -- bash -lc 'cd /mnt/c/Users/unkno/dev/CoinCync && cargo build --release --bin coincync-node --features testnet'

.PARAMETER Nodes
  IPs of the fleet boxes. Pass 4+ so each node reaches >=3 peers.

.PARAMETER Seed
  Public seed each node also dials, as IP:PORT. Default 2.28.1.75:28080.

.PARAMETER DryRun
  Print the per-node plan (incl. each unit's --addnode list) without touching
  any remote.

.EXAMPLE
  .\scripts\deploy-testnet-fleet.ps1 -Nodes 62.238.121.186,<ip2>,<ip3>,<ip4> -DryRun
.EXAMPLE
  .\scripts\deploy-testnet-fleet.ps1 -Nodes 62.238.121.186,<ip2>,<ip3>,<ip4>
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string[]]$Nodes,
  [string]$Seed = '2.28.1.75:28080',
  [string]$KeyPath = "$env:USERPROFILE\.ssh\coincync_fleet",
  [int]$P2pPort = 28080,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'
$RepoRoot   = Resolve-Path "$PSScriptRoot\.."
$BinaryPath = Join-Path $RepoRoot 'target\release\coincync-node'

# --- Pre-flight ------------------------------------------------------
if (-not (Test-Path $KeyPath)) { throw "SSH key not found: $KeyPath" }
if (-not (Test-Path $BinaryPath)) {
  Write-Host "ERROR: missing Linux node binary: $BinaryPath" -ForegroundColor Red
  Write-Host "  Build via: wsl -- bash -lc 'cd /mnt/c/Users/unkno/dev/CoinCync && cargo build --release --bin coincync-node --features testnet'" -ForegroundColor Yellow
  exit 1
}
if ($Nodes.Count -lt 4) {
  Write-Host "WARNING: $($Nodes.Count) nodes given. Each will see $($Nodes.Count - 1) fleet peer(s); the >=3 gate needs 4+ nodes (the seed is unreliable)." -ForegroundColor Yellow
}

# LogLevel=ERROR silences scp/ssh's "Permanently added ... to known hosts"
# banner, which PowerShell 5.1 would otherwise escalate to a terminating error.
$sshOpts = @('-i', $KeyPath, '-o', 'StrictHostKeyChecking=accept-new', '-o', 'ConnectTimeout=10', '-o', 'LogLevel=ERROR')
# Native-command stderr must not abort the per-node loop.
$ErrorActionPreference = 'Continue'

Write-Host ("=" * 68)
Write-Host "  CoinCync testnet fleet deploy - $($Nodes.Count) nodes" -ForegroundColor Cyan
Write-Host "  seed:   $Seed"
$binBytes = (Get-Item $BinaryPath).Length
Write-Host "  binary: $BinaryPath ($binBytes bytes)"
Write-Host ("=" * 68)

foreach ($ip in $Nodes) {
  $peers = @($Nodes | Where-Object { $_ -ne $ip })
  $addnode = (($peers | ForEach-Object { "--addnode $($_):$P2pPort" }) + @("--addnode $Seed")) -join ' '

  # Generate the unit with LF endings (a CRLF unit breaks systemd parsing).
  $unitLines = @(
    '[Unit]'
    'Description=CoinCync testnet node (fleet mesh)'
    'After=network-online.target'
    'Wants=network-online.target'
    ''
    '[Service]'
    'Type=simple'
    'User=coincync'
    'Group=coincync'
    "ExecStart=/usr/local/bin/coincync-node --network testnet --data-dir /var/lib/coincync --rest-disable --external-ip $ip $addnode"
    'Restart=on-failure'
    'RestartSec=5'
    'LimitNOFILE=65536'
    'NoNewPrivileges=true'
    'PrivateTmp=true'
    'ProtectSystem=strict'
    'ProtectHome=true'
    'ReadWritePaths=/var/lib/coincync'
    'ProtectKernelTunables=true'
    'ProtectControlGroups=true'
    'RestrictSUIDSGID=true'
    ''
    '[Install]'
    'WantedBy=multi-user.target'
  )
  $tmpUnit = [IO.Path]::GetTempFileName()
  [IO.File]::WriteAllText($tmpUnit, ($unitLines -join "`n") + "`n")

  # Single `;`-joined remote install - NO heredoc, so no CRLF trap. P2P is
  # public (lets the mesh grow + other nodes dial in); RPC stays loopback.
  $install = @(
    'id -u coincync >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin coincync'
    'mkdir -p /var/lib/coincync /etc/coincync'
    'chown coincync:coincync /var/lib/coincync'
    # Atomic swap: mv is rename(2), which replaces even a running binary
    # (a direct overwrite fails with text-file-busy).
    'chmod 0755 /usr/local/bin/coincync-node.new'
    'chown root:root /usr/local/bin/coincync-node.new'
    'mv -f /usr/local/bin/coincync-node.new /usr/local/bin/coincync-node'
    "command -v ufw >/dev/null 2>&1 && { ufw allow 22/tcp >/dev/null; ufw allow $P2pPort/tcp >/dev/null; } || true"
    'systemctl daemon-reload'
    'systemctl enable coincync-node >/dev/null 2>&1'
    'systemctl restart coincync-node'
    'sleep 3'
    'systemctl is-active coincync-node'
  ) -join '; '

  Write-Host ""
  Write-Host "-- $ip --" -ForegroundColor Green
  Write-Host "  addnode: $addnode"
  if ($DryRun) {
    Write-Host "  DRY RUN - would scp binary + unit and run install." -ForegroundColor Yellow
    Remove-Item $tmpUnit -Force
    continue
  }

  Write-Host "  pushing binary + unit..."
  & scp @sshOpts $BinaryPath "root@${ip}:/usr/local/bin/coincync-node.new" 2>&1 | ForEach-Object { Write-Host "    $_" }
  & scp @sshOpts $tmpUnit    "root@${ip}:/etc/systemd/system/coincync-node.service" 2>&1 | ForEach-Object { Write-Host "    $_" }
  Remove-Item $tmpUnit -Force

  Write-Host "  installing..."
  $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
  & ssh @sshOpts "root@${ip}" $install 2>&1 | ForEach-Object { Write-Host "    $_" }
  if ($LASTEXITCODE -ne 0) { Write-Host "  ERROR: install failed on $ip (exit $LASTEXITCODE)" -ForegroundColor Red }
  $ErrorActionPreference = $prev
}

Write-Host ""
Write-Host ("=" * 68)
Write-Host "Done. Give the mesh ~1-2 min to interconnect, then check peer counts:" -ForegroundColor Cyan
foreach ($ip in $Nodes) {
  Write-Host "  ssh -i `$env:USERPROFILE\.ssh\coincync_fleet root@$ip `"journalctl -u coincync-node -n 5 --no-pager | grep -i 'peer maintenance'`""
}
Write-Host ""
Write-Host "When every node reports 'peers=3' (or more) and is synced, deploy the"
Write-Host "miner to your dedicated box - it'll clear the gate and start mining."
