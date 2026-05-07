#requires -Version 5.1
<#
.SYNOPSIS
  Post a message to a Discord webhook. Used for the weekly dev log
  and other manual posts to project channels (#dev-log, #announcements).

.DESCRIPTION
  Wraps the Discord webhook API. Reads message content from a file,
  the -Body parameter, or stdin (whichever is provided). Splits messages
  longer than Discord's 2000-char limit across multiple posts so a
  weekly log of any reasonable size goes through cleanly.

  The webhook URL is sensitive (anyone with it can post as the bot to
  the channel). Default is to read from the env var
  $env:COINCYNC_DEV_LOG_WEBHOOK so the URL never lives in shell
  history or committed scripts.

.PARAMETER WebhookUrl
  Discord webhook URL. Default: read from $env:COINCYNC_DEV_LOG_WEBHOOK.

.PARAMETER File
  Path to a markdown file. The file's contents become the message.

.PARAMETER Body
  Inline message string. Mutually exclusive with -File.

.PARAMETER Username
  Override the webhook's display name for this post.
  Example: -Username 'CoinCync Dev Log'

.PARAMETER DryRun
  Print what would be posted without actually hitting Discord.

.EXAMPLE
  # Set the webhook URL once per shell session
  $env:COINCYNC_DEV_LOG_WEBHOOK = 'https://discord.com/api/webhooks/.../...'

  # Post the rendered weekly log
  .\scripts\post-to-discord.ps1 -File .\tmp\devlog-2026-05-11.md

.EXAMPLE
  # Post a one-line status update
  .\scripts\post-to-discord.ps1 -Body 'Faucet health: OK. 47 drips today, 0 failures.'

.EXAMPLE
  # Read a file's contents into a variable, then post:
  $msg = Get-Content .\soak-status.txt -Raw
  .\scripts\post-to-discord.ps1 -Body $msg
#>

param(
  [string]$WebhookUrl = $env:COINCYNC_DEV_LOG_WEBHOOK,
  [string]$File,
  [string]$Body,
  [string]$Username,
  [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# Discord's hard cap on message content.
$MaxChars = 1900  # Leave headroom — Discord's actual limit is 2000.

if (-not $WebhookUrl) {
  Write-Host "FAIL: webhook URL not set." -ForegroundColor Red
  Write-Host "Either pass -WebhookUrl <url> or set:" -ForegroundColor Yellow
  Write-Host '  $env:COINCYNC_DEV_LOG_WEBHOOK = "https://discord.com/api/webhooks/.../..."' -ForegroundColor Yellow
  exit 1
}

# Resolve message text. -File and -Body are mutually exclusive; -File wins.
if ($File) {
  if (-not (Test-Path $File)) {
    Write-Host "FAIL: file not found: $File" -ForegroundColor Red
    exit 1
  }
  $messageText = Get-Content -Path $File -Raw
} elseif ($Body) {
  $messageText = $Body
} else {
  Write-Host "FAIL: no message content." -ForegroundColor Red
  Write-Host "Pass -File <path> or -Body '<text>'." -ForegroundColor Yellow
  Write-Host "To send a captured string:" -ForegroundColor Yellow
  Write-Host '  $msg = Get-Content soak.txt -Raw' -ForegroundColor DarkGray
  Write-Host '  .\scripts\post-to-discord.ps1 -Body $msg' -ForegroundColor DarkGray
  exit 1
}

if (-not $messageText -or $messageText.Trim().Length -eq 0) {
  Write-Host "FAIL: message body is empty." -ForegroundColor Red
  exit 1
}

# Split message into <= $MaxChars chunks at line boundaries when possible.
function Split-Message {
  param([string]$Text, [int]$Max)
  $chunks = @()
  $current = ''
  foreach ($line in $Text -split "`r?`n", 0) {
    $candidate = if ($current.Length -eq 0) { $line } else { "$current`n$line" }
    if ($candidate.Length -le $Max) {
      $current = $candidate
    } else {
      if ($current.Length -gt 0) { $chunks += $current }
      # If this single line is itself too long, hard-split it.
      if ($line.Length -gt $Max) {
        for ($i = 0; $i -lt $line.Length; $i += $Max) {
          $end = [Math]::Min($i + $Max, $line.Length)
          $chunks += $line.Substring($i, $end - $i)
        }
        $current = ''
      } else {
        $current = $line
      }
    }
  }
  if ($current.Length -gt 0) { $chunks += $current }
  # Comma-prefix forces array preservation; without it, a single-element
  # array unrolls to a scalar string and $chunks[0] returns one character.
  return ,$chunks
}

$chunks = Split-Message -Text $messageText -Max $MaxChars

Write-Host "Posting $($chunks.Count) chunk(s) to Discord..." -ForegroundColor Cyan

for ($i = 0; $i -lt $chunks.Count; $i += 1) {
  $payload = @{ content = $chunks[$i] }
  if ($Username) { $payload.username = $Username }
  $json = $payload | ConvertTo-Json -Compress

  if ($DryRun) {
    Write-Host "--- chunk $($i + 1) / $($chunks.Count) (dry run) ---" -ForegroundColor DarkGray
    Write-Host $chunks[$i]
    Write-Host "--- end chunk ---" -ForegroundColor DarkGray
    continue
  }

  try {
    $resp = Invoke-RestMethod -Uri $WebhookUrl `
                              -Method Post `
                              -ContentType 'application/json' `
                              -Body $json `
                              -TimeoutSec 15
    Write-Host "  chunk $($i + 1) / $($chunks.Count) posted" -ForegroundColor Green
  } catch {
    Write-Host "FAIL: chunk $($i + 1) post failed: $_" -ForegroundColor Red
    if ($_.Exception.Response) {
      $stream = $_.Exception.Response.GetResponseStream()
      $reader = New-Object System.IO.StreamReader($stream)
      Write-Host "  response: $($reader.ReadToEnd())" -ForegroundColor DarkRed
    }
    exit 1
  }

  # Discord rate-limits webhooks at ~5 req/sec. Pace ourselves.
  if ($i -lt $chunks.Count - 1) { Start-Sleep -Milliseconds 300 }
}

if (-not $DryRun) {
  Write-Host ''
  Write-Host "Done." -ForegroundColor Green
}
