#requires -Version 5.1
<#
provision-vultr-fleet.ps1 — bring up the new Vultr fleet from local backup.

Stand-up plan:
- 3 SEED nodes (NJ, AMS, Tokyo): coincync-node testnet, P2P 28080 public,
  RPC 28081 loopback. Each seed gets --addnode flags for the other two so
  the fleet self-peers without depending on DNS.
- 2 SERVICE nodes (Dallas explorer, Frankfurt api): same coincync-node,
  same data dir layout, but no --addnode (they use DNS to find seeds).
  Nginx + RPC API key setup is a SEPARATE step after this script.

Idempotent: re-running it on an already-provisioned box just refreshes the
binary + service. Safe to retry on failure.

Pre-reqs (verify before running):
  1. SSH key at $env:USERPROFILE\.ssh\coincync_fleet authorised on all 5 boxes
  2. Local binary at release\v1.0.1-testnet\coincync-node-linux-x86_64
  3. Chain snapshot at fleet-backup-20260502T203842Z\fleet-backup-20260502T203842Z\chain-snapshot-NYC3.tar.gz
  4. systemd unit template at deploy\coincync-node.service
#>

$ErrorActionPreference = 'Stop'

# ─── config ──────────────────────────────────────────────────────────────
$RepoRoot = Resolve-Path "$PSScriptRoot\.."
$KeyPath  = "$env:USERPROFILE\.ssh\coincync_fleet"
$Binary   = Join-Path $RepoRoot 'release\v1.0.1-testnet\coincync-node-linux-x86_64'
$Snapshot = Join-Path $RepoRoot 'fleet-backup-20260502T203842Z\fleet-backup-20260502T203842Z\chain-snapshot-NYC3.tar.gz'
$Unit     = Join-Path $RepoRoot 'deploy\coincync-node.service'

# Role → IP map. Seeds get cross-addnode; service boxes don't.
$Fleet = @(
  @{ Role='seed';    Name='seed1';    IP='66.135.23.193'  },
  @{ Role='seed';    Name='seed2';    IP='140.82.57.168'  },
  @{ Role='seed';    Name='seed3';    IP='207.148.111.76' },
  @{ Role='service'; Name='explorer'; IP='207.148.6.50'   },
  @{ Role='service'; Name='api';      IP='95.179.165.225' }
)

# ─── pre-flight ──────────────────────────────────────────────────────────
foreach ($f in @($KeyPath, $Binary, $Snapshot, $Unit)) {
  if (-not (Test-Path $f)) { throw "Missing: $f" }
}

$seedIps = ($Fleet | Where-Object { $_.Role -eq 'seed' } | ForEach-Object { $_.IP })

# ─── per-box provisioning ────────────────────────────────────────────────
function Invoke-Ssh($ip, $script) {
  # Write the script to a local temp file as UTF-8 with NO BOM, scp it,
  # exec it remotely. Avoids PowerShell's stdin encoding adding a BOM
  # that crashes bash on line 1 ("set: command not found").
  $tmpLocal = [System.IO.Path]::GetTempFileName()
  try {
    [System.IO.File]::WriteAllText($tmpLocal, $script, [System.Text.UTF8Encoding]::new($false))
    & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $tmpLocal "root@${ip}:/tmp/provision-coincync.sh"
    if ($LASTEXITCODE -ne 0) { throw "SCP of provision script to $ip failed" }
    & ssh -i $KeyPath -o StrictHostKeyChecking=accept-new -o ConnectTimeout=15 `
        "root@$ip" "bash /tmp/provision-coincync.sh; ec=`$?; rm -f /tmp/provision-coincync.sh; exit `$ec"
    if ($LASTEXITCODE -ne 0) { throw "SSH to $ip exited with $LASTEXITCODE" }
  } finally {
    Remove-Item -Force -ErrorAction SilentlyContinue $tmpLocal
  }
}

function Invoke-Scp($src, $ip, $dst) {
  & scp -i $KeyPath -o StrictHostKeyChecking=accept-new -q $src "root@${ip}:$dst"
  if ($LASTEXITCODE -ne 0) { throw "SCP to $ip failed" }
}

foreach ($node in $Fleet) {
  $ip   = $node.IP
  $name = $node.Name
  $role = $node.Role

  Write-Host ""
  Write-Host "════════════════════════════════════════════════════════════════"
  Write-Host "  $name ($role) @ $ip"
  Write-Host "════════════════════════════════════════════════════════════════"

  # 1. Upload artifacts
  Write-Host "[1/5] Uploading binary, snapshot, systemd unit..."
  Invoke-Scp $Binary   $ip '/tmp/coincync-node'
  if ($role -eq 'seed') {
    Invoke-Scp $Snapshot $ip '/tmp/chain-snapshot.tar.gz'
  }
  Invoke-Scp $Unit     $ip '/tmp/coincync-node.service.tmpl'

  # 2. Build per-box systemd unit content
  if ($role -eq 'seed') {
    # Seeds get --addnode for the OTHER two seeds (not themselves)
    $peers = $seedIps | Where-Object { $_ -ne $ip } |
             ForEach-Object { "--addnode $($_):28080" }
    $extraArgs = $peers -join ' '
  } else {
    # Service boxes use DNS-based bootstrap (the testnet binary has
    # seed1-3.coincync.network hardcoded; those now resolve to Vultr IPs).
    $extraArgs = ''
  }

  # 3. Run remote provisioning
  Write-Host "[2/5] Creating user + data dir + installing binary..."
  Write-Host "[3/5] Restoring snapshot (seeds only) + writing systemd unit..."
  Write-Host "[4/5] Configuring UFW..."
  Write-Host "[5/5] Starting service + verifying..."

  $remote = @"
set -euo pipefail

# User + data dir
id -u coincync >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin coincync
install -d -o coincync -g coincync -m 0750 /var/lib/coincync

# Binary
install -m 0755 /tmp/coincync-node /usr/local/bin/coincync-node
rm -f /tmp/coincync-node

# Snapshot (seeds only — service boxes will sync from seeds)
if [ -f /tmp/chain-snapshot.tar.gz ]; then
  systemctl stop coincync-node 2>/dev/null || true
  rm -rf /var/lib/coincync/testnet
  sudo -u coincync tar -xzf /tmp/chain-snapshot.tar.gz -C /var/lib/coincync
  rm -f /tmp/chain-snapshot.tar.gz
fi

# systemd unit — start from template, append --addnode flags for seeds
cp /tmp/coincync-node.service.tmpl /etc/systemd/system/coincync-node.service
rm -f /tmp/coincync-node.service.tmpl
EXTRA_ARGS='$extraArgs'
if [ -n "`$EXTRA_ARGS" ]; then
  # Inject peer flags into the ExecStart line. The template ends ExecStart with --log-level info \\
  # We append after that, before the next directive.
  sed -i "s|--log-level info|--log-level info `$EXTRA_ARGS|" /etc/systemd/system/coincync-node.service
fi
systemctl daemon-reload

# UFW (idempotent)
if ! command -v ufw >/dev/null 2>&1; then apt-get update -qq && apt-get install -yqq ufw; fi
ufw --force reset >/dev/null
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH'
ufw allow 28080/tcp comment 'CoinCync P2P testnet'
case "$name" in
  explorer|api)
    ufw allow 80/tcp comment 'HTTP'
    ufw allow 443/tcp comment 'HTTPS'
    ;;
esac
ufw --force enable >/dev/null

# Start service
systemctl enable --now coincync-node
sleep 5

# Verify
if ! systemctl is-active --quiet coincync-node; then
  echo "FAIL: coincync-node not active. Last 50 log lines:"
  journalctl -u coincync-node -n 50 --no-pager
  exit 1
fi

# Print height/tip from the running node (single-line, no shell-line-continuation)
sudo -u coincync /usr/local/bin/coincync-node --data-dir /var/lib/coincync --network testnet status 2>&1 | grep -E 'Network|Height|Tip' || true

echo "OK: $name provisioned"
"@

  Invoke-Ssh $ip $remote
}

Write-Host ""
Write-Host "════════════════════════════════════════════════════════════════"
Write-Host "  Fleet provisioning complete"
Write-Host "════════════════════════════════════════════════════════════════"
Write-Host "Next: verify peer counts (coincync-node-cli or curl RPC) and"
Write-Host "confirm seed1/2/3 have each other in their peer lists."
