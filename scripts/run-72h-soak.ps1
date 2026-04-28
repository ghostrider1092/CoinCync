param([string]$OutFile)
$headers=@{ Authorization='Bearer 6430f9425dcd29549017499686852edb504f20ba1ee8a97c8a14eff8a62f0a48' }
$body='{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}'
$end=(Get-Date).AddHours(72)
"{""event"":""start"",""utc"":""$([DateTime]::UtcNow.ToString('o'))""}" | Out-File -FilePath $OutFile -Encoding utf8 -Append
while((Get-Date) -lt $end){
  $utc=[DateTime]::UtcNow.ToString('o')
  $localOk=$false; $expOk=$false
  $localH=$null; $localTip=$null; $localAge=$null; $localErr=$null
  $expH=$null; $expTip=$null; $expAge=$null; $expErr=$null
  try {
    $l=Invoke-RestMethod -Uri 'http://127.0.0.1:28081' -Method Post -Headers $headers -ContentType 'application/json' -Body $body -TimeoutSec 15
    $localOk=$true; $localH=$l.result.height; $localTip=$l.result.tip_hash; $localAge=$l.result.tip_age_secs
  } catch { $localErr=$_.Exception.Message }
  try {
    $e=Invoke-RestMethod -Uri 'https://explorer.coincync.network/api/testnet' -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 20
    $expOk=$true; $expH=$e.result.height; $expTip=$e.result.tip_hash; $expAge=$e.result.tip_age_secs
  } catch { $expErr=$_.Exception.Message }
  $same=$false
  if($localOk -and $expOk -and $localTip -and $expTip){ $same=($localTip -eq $expTip) }
  $obj=[ordered]@{utc=$utc; local_ok=$localOk; explorer_ok=$expOk; same_tip=$same; local_height=$localH; explorer_height=$expH; local_tip=$localTip; explorer_tip=$expTip; local_tip_age_secs=$localAge; explorer_tip_age_secs=$expAge; local_error=$localErr; explorer_error=$expErr}
  ($obj | ConvertTo-Json -Compress) | Out-File -FilePath $OutFile -Encoding utf8 -Append
  Start-Sleep -Seconds 60
}
"{""event"":""end"",""utc"":""$([DateTime]::UtcNow.ToString('o'))""}" | Out-File -FilePath $OutFile -Encoding utf8 -Append
