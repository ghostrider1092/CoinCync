param(
  [string]$LogFile,
  [string]$WebhookConfig = "discord_webhooks.json",
  [int]$ReminderMinutes = 15
)

if (-not (Test-Path $LogFile)) { Write-Error "Log file not found: $LogFile"; exit 1 }

$webhookUrl = $null
if (Test-Path $WebhookConfig) {
  try {
    $cfg = Get-Content -Raw -Path $WebhookConfig | ConvertFrom-Json
    if ($cfg.stats_webhook) { $webhookUrl = [string]$cfg.stats_webhook }
    elseif ($cfg.github_webhook) { $webhookUrl = [string]$cfg.github_webhook }
  } catch {
    Write-Output ("WEBHOOK_CONFIG_ERROR " + $_.Exception.Message)
  }
}

function Send-Discord([string]$message) {
  if (-not $webhookUrl) { return }
  try {
    $payload = @{ content = $message } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri $webhookUrl -Method Post -ContentType "application/json" -Body $payload -TimeoutSec 15 | Out-Null
  } catch {
    Write-Output ("DISCORD_SEND_ERROR " + $_.Exception.Message)
  }
}

function Send-Desktop([string]$message) {
  try {
    msg * $message | Out-Null
  } catch {
    Write-Output ("DESKTOP_ALERT_ERROR " + $_.Exception.Message)
  }
}

Write-Output "watching=$LogFile"
if ($webhookUrl) { Write-Output "discord=enabled" } else { Write-Output "discord=disabled" }

$seen = 0
$inFailure = $false
$lastFailureAlert = [datetime]::MinValue
$reminderSpan = [timespan]::FromMinutes([Math]::Max(1, $ReminderMinutes))

while ($true) {
  try {
    $lines = Get-Content -Path $LogFile
    if ($lines.Count -gt $seen) {
      for ($i = $seen; $i -lt $lines.Count; $i++) {
        $line = $lines[$i]
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try {
          $o = $line | ConvertFrom-Json
        } catch { continue }
        if ($o.event -eq 'start' -or $o.event -eq 'end') { continue }

        $bad = (-not $o.local_ok) -or (-not $o.explorer_ok) -or (-not $o.same_tip)
        if ($bad) {
          $short = "SOAK ALERT: local_ok=$($o.local_ok) explorer_ok=$($o.explorer_ok) same_tip=$($o.same_tip) local_h=$($o.local_height) explorer_h=$($o.explorer_height) utc=$($o.utc)"
          $full = "$short local_err=$($o.local_error) explorer_err=$($o.explorer_error)"
          Write-Output ("ALERT " + $full)

          $now = Get-Date
          $shouldNotify = (-not $inFailure) -or (($now - $lastFailureAlert) -ge $reminderSpan)
          if ($shouldNotify) {
            Send-Discord $full
            Send-Desktop $short
            $lastFailureAlert = $now
          }
          $inFailure = $true
        } else {
          Write-Output ("OK utc=" + $o.utc + " h=" + $o.local_height + " tip=" + $o.local_tip.Substring(0,16))
          if ($inFailure) {
            $recover = "SOAK RECOVERED: local and explorer are healthy + synced again at utc=$($o.utc), height=$($o.local_height)"
            Write-Output ("RECOVERY " + $recover)
            Send-Discord $recover
            Send-Desktop $recover
            $inFailure = $false
          }
        }
      }
      $seen = $lines.Count
    }
  } catch {
    Write-Output ("WATCHER_ERROR " + $_.Exception.Message)
  }
  Start-Sleep -Seconds 30
}
