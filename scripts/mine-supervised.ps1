<#
.SYNOPSIS
  Supervised wrapper for `coincync-rig run-solo` on Windows.

.DESCRIPTION
  The RandomX light-mode + JIT path intermittently dies from an
  UNCATCHABLE native crash (a JIT execute-memory access violation inside
  randomx_rs) during steady-state mining. It is not a seed/epoch event
  (the epoch key is constant below height 2048) and not a Rust error
  (the mining worker already swallows hash `Err`s) -- it is a segfault
  that kills the whole process, so no in-process handler can recover it.

  The correct fix for an uncatchable native crash is external process
  supervision, exactly as every production miner (xmrig, p2pool) is run.
  The node persists the chain, so a freshly relaunched rig simply resumes
  from the current tip; the only cost per crash is ~2s + a light-cache
  rebuild. On Linux this is the systemd unit's `Restart=always`; this
  script is the Windows equivalent.

  Ctrl+C stops the supervisor cleanly (it will not relaunch after an
  operator-initiated stop).

.EXAMPLE
  # Home miner: 8 threads against the local testnet node.
  powershell -ExecutionPolicy Bypass -File scripts\mine-supervised.ps1 `
    -Address <your-testnet-address> -Threads 8

.EXAMPLE
  # Explicit node + regtest.
  .\scripts\mine-supervised.ps1 -Node http://127.0.0.1:18081 `
    -Address <addr> -Network regtest -Threads 4
#>
[CmdletBinding()]
param(
  [string]$RigBin = "",                      # auto-detected if empty
  [string]$Node = "http://127.0.0.1:28081",  # local testnet RPC by default
  [Parameter(Mandatory = $true)]
  [string]$Address,
  [ValidateSet("mainnet", "testnet", "regtest")]
  [string]$Network = "testnet",
  [int]$Threads = 8,
  [int]$PollIntervalSecs = 60,
  [switch]$LightMode = $true,                # COINCYNC_RANDOMX_LIGHT_MODE=1
  [string]$LogFile = ""                       # optional supervisor log
)

$ErrorActionPreference = "Stop"

# --- resolve the rig binary ---------------------------------------------
if ([string]::IsNullOrWhiteSpace($RigBin)) {
  $repoRoot = Split-Path -Parent $PSScriptRoot
  $candidates = @(
    (Join-Path $repoRoot "target\release\coincync-rig.exe"),
    (Join-Path $repoRoot "target\debug\coincync-rig.exe")
  )
  foreach ($c in $candidates) { if (Test-Path $c) { $RigBin = $c; break } }
}
if ([string]::IsNullOrWhiteSpace($RigBin) -or -not (Test-Path $RigBin)) {
  Write-Error "coincync-rig.exe not found. Pass -RigBin <path> (looked under target\release and target\debug)."
  exit 1
}

# Light mode is a per-process env var read by the RandomX cache builder.
if ($LightMode) { $env:COINCYNC_RANDOMX_LIGHT_MODE = "1" }

function Write-Log {
  param([string]$Message)
  $line = "[{0}] {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
  Write-Host $line
  if (-not [string]::IsNullOrWhiteSpace($LogFile)) {
    Add-Content -Path $LogFile -Value $line -Encoding utf8
  }
}

$rigArgs = @(
  "run-solo",
  "--node", $Node,
  "--address", $Address,
  "--network", $Network,
  "--threads", "$Threads",
  "--poll-interval-secs", "$PollIntervalSecs"
)

Write-Log ("supervisor starting: {0} {1}" -f $RigBin, ($rigArgs -join " "))
Write-Log ("light_mode={0}  (Ctrl+C to stop; the supervisor will not relaunch after a clean stop)" -f [bool]$LightMode)

# --- crash-loop backoff --------------------------------------------------
# A healthy crash is rare (minutes to hours apart); if the rig instead
# exits within a few seconds repeatedly, something is fundamentally wrong
# (bad address, node down, missing feature build) and hammering restart
# makes it worse. Escalate the delay when restarts come too fast, reset
# it once the rig has run for a meaningful stretch.
$minBackoff = 3
$maxBackoff = 60
$backoff = $minBackoff
$fastExitThresholdSecs = 20   # ran shorter than this => treat as crash-loop
$restarts = 0

while ($true) {
  $startedAt = Get-Date
  try {
    # Start-Process -Wait -PassThru surfaces the child exit code, and
    # -NoNewWindow keeps the rig's stdout/stderr in this console/journal.
    $proc = Start-Process -FilePath $RigBin -ArgumentList $rigArgs `
      -NoNewWindow -PassThru -Wait
    $code = $proc.ExitCode
  } catch {
    Write-Log ("launch error: {0}" -f $_.Exception.Message)
    $code = -1
  }

  $ranSecs = [int]((Get-Date) - $startedAt).TotalSeconds
  $restarts++
  Write-Log ("rig exited: code={0}  ran={1}s  (restart #{2})" -f $code, $ranSecs, $restarts)

  if ($ranSecs -ge $fastExitThresholdSecs) {
    # Healthy long run before the crash — reset the backoff so the next
    # relaunch is prompt.
    $backoff = $minBackoff
  } else {
    # Fast exit => likely a persistent misconfig, not the sporadic JIT
    # crash. Back off exponentially so we don't hot-loop.
    Write-Log ("fast exit (<{0}s): backing off {1}s before relaunch (misconfig? check node/address/build)" -f $fastExitThresholdSecs, $backoff)
    Start-Sleep -Seconds $backoff
    $backoff = [Math]::Min($backoff * 2, $maxBackoff)
    continue
  }

  Write-Log ("relaunching in {0}s..." -f $minBackoff)
  Start-Sleep -Seconds $minBackoff
}
