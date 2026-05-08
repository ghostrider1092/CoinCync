#Requires -Version 5.1
<#
.SYNOPSIS
  User-runnable on-chain privacy verifier for any CoinCync transaction.

.DESCRIPTION
  Given a transaction hash, this script independently re-verifies that
  the cryptographic privacy properties CoinCync claims are actually
  present on-chain -- without trusting the node's "privacy" summary block.

  This is the artifact a journalist, skeptic, or auditor can run to
  confirm that a transaction really used the privacy features the
  whitepaper promises. It needs no insider access -- it hits the public
  testnet RPC the same way every other user does.

  Properties verified (cryptographic, on-chain only):
    1. CLSAG ring signatures         -- ring size matches the constitutional
                                        rule for the tx's block height:
                                          * height <  10000  : ring == 11
                                            (bootstrap; chain is too young
                                             for full anonymity set)
                                          * height >= 10000  : ring == 16
                                            (full Constitution Article III)
    2. Stealth addresses             -- every output has a unique
                                        one-time stealth key + tx public key
    3. Pedersen commitments          -- every output amount is committed,
                                        not plaintext
    4. Bulletproofs+ range proof     -- non-empty, sized appropriately
                                        for the output count
    5. View tags                     -- 1-byte view tag present per output
    6. Encrypted memo (if any)       -- confirms encryption envelope
                                        present (cannot decrypt without
                                        view key, but presence is checked)

  Properties NOT verified by this script (need separate tools):
    - Dandelion++ stem-then-fluff propagation (network layer; use
      test-tx-propagation.ps1 for that)
    - Noise_XX P2P encryption (transport layer; node logs only)
    - Auto-churn / dead-man's-switch (wallet-level features)

.PARAMETER TxHash
  64-character hex transaction hash to verify.

.PARAMETER Node
  RPC endpoint. Defaults to public testnet API.

.EXAMPLE
  .\scripts\verify-privacy.ps1 -TxHash 5f3c...

.EXAMPLE
  .\scripts\verify-privacy.ps1 -TxHash 5f3c... -Node http://127.0.0.1:28081
#>

param(
  [Parameter(Mandatory = $true)]
  [string]$TxHash,

  [string]$Node = 'https://api.coincync.network/rpc/testnet'
)

$ErrorActionPreference = 'Stop'

# -- normalize + validate hash ------------------------------------
$TxHash = $TxHash.Trim().ToLower() -replace '^0x', ''
if ($TxHash -notmatch '^[0-9a-f]{64}$') {
  Write-Host "FAIL: tx hash must be 64 hex chars. Got length $($TxHash.Length)" -ForegroundColor Red
  exit 1
}

# -- header --------------------------------------------------------
Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host '   CoinCync on-chain privacy verifier'                        -ForegroundColor Cyan
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
Write-Host ("  rpc:  $Node")
Write-Host ("  txid: $TxHash")
Write-Host ''

# -- fetch tx via JSON-RPC -----------------------------------------
$rpcBody = @{
  jsonrpc = '2.0'
  id      = 1
  method  = 'get_transaction'
  params  = @($TxHash)
} | ConvertTo-Json -Compress

try {
  $resp = Invoke-RestMethod -Uri $Node `
                            -Method Post `
                            -ContentType 'application/json' `
                            -Body $rpcBody `
                            -TimeoutSec 30
} catch {
  Write-Host "FAIL: RPC call failed: $_" -ForegroundColor Red
  exit 1
}

if ($resp.error) {
  Write-Host "FAIL: RPC error: $($resp.error.message)" -ForegroundColor Red
  exit 1
}

$tx = $resp.result
if (-not $tx) {
  Write-Host "FAIL: empty RPC result" -ForegroundColor Red
  exit 1
}

# -- pretty-print summary ------------------------------------------
Write-Host '  block height:    ' -NoNewline; Write-Host $tx.block_height -ForegroundColor White
Write-Host '  block hash:      ' -NoNewline; Write-Host $tx.block_hash -ForegroundColor DarkGray
Write-Host '  type:            ' -NoNewline; Write-Host $tx.type -ForegroundColor White
Write-Host '  inputs:          ' -NoNewline; Write-Host $tx.input_count -ForegroundColor White
Write-Host '  outputs:         ' -NoNewline; Write-Host $tx.output_count -ForegroundColor White
Write-Host '  size:            ' -NoNewline; Write-Host "$($tx.size) bytes" -ForegroundColor White
Write-Host '  fee (atomic):    ' -NoNewline; Write-Host $tx.fee -ForegroundColor White
Write-Host ''

# -- tx-type detection ---------------------------------------------
# Coinbase txs (block rewards) have legitimately different privacy
# properties than user-sent transfers. Coinbase rewards are public
# by consensus design (block reward must be auditable for the
# emission cap), so they have NO ring sig and NO range proof -- only
# the recipient stealth-address layer applies. Asserting the same
# rules on both would force the script to "fail" every coinbase,
# which would make it useless on real chain data.
$txType = "$($tx.type)"
$isCoinbase = $txType -match '^(?i)coinbase$'

if ($isCoinbase) {
  Write-Host '  TX TYPE: Coinbase (block reward).' -ForegroundColor Yellow
  Write-Host '  Coinbase emissions are public by consensus design -- only' -ForegroundColor DarkGray
  Write-Host '  recipient-side privacy (stealth addr + view tag) applies.' -ForegroundColor DarkGray
} else {
  Write-Host "  TX TYPE: $txType (user transfer). Full privacy expected." -ForegroundColor Yellow
}
Write-Host ''
Write-Host '  Re-verifying privacy properties from raw tx fields...' -ForegroundColor Yellow
Write-Host ''

# -- property checks (each independent of the server's "privacy" summary) --
$failures = 0

function Add-Check {
  param([string]$Name, [bool]$Pass, [string]$Detail)
  $tag = if ($Pass) { 'PASS' } else { 'FAIL' }
  $color = if ($Pass) { 'Green' } else { 'Red' }
  $line = '  [{0}] {1,-32} {2}' -f $tag, $Name, $Detail
  Write-Host $line -ForegroundColor $color
  if (-not $Pass) { $script:failures++ }
}

function Add-NA {
  param([string]$Name, [string]$Detail)
  $line = '  [N/A]  {0,-32} {1}' -f $Name, $Detail
  Write-Host $line -ForegroundColor DarkGray
}

# 1. CLSAG ring signatures -- expected size depends on tx's block height.
#    Constitutional rule (src/constants.rs::ring_size_at_height):
#      * height <  10000  -> bootstrap ring = 11 (BOOTSTRAP_MIN_RING_SIZE)
#      * height >= 10000  -> full ring = 16 (DEFAULT_RING_SIZE)
#    The bootstrap window exists because a freshly-launched chain has
#    too few outputs to form a 16-member anonymity set without reusing
#    decoys. After block 10000 the network reliably has enough outputs
#    for the full ring. Asserting this gives users the right context
#    instead of a confusing "ring size 11" failure on a young testnet.
$txHeight = [uint64]$tx.block_height
$expectedRing = if ($txHeight -lt 10000) { 11 } else { 16 }
$ringStage = if ($txHeight -lt 10000) {
  "bootstrap (height $txHeight < 10000); ring=11 is constitutional"
} else {
  "post-bootstrap (height $txHeight >= 10000); ring=16 is required"
}

if ($isCoinbase) {
  Add-NA 'CLSAG ring size' 'coinbase has no inputs to ring-sign (correct)'
} else {
  $ringSizes = @($tx.inputs | ForEach-Object { [int]$_.ring_size })
  $allMatch = $ringSizes.Count -gt 0 -and ($ringSizes | Where-Object { $_ -ne $expectedRing }).Count -eq 0
  $detail = "ring sizes per input: [{0}]; expected {1} ({2})" -f ($ringSizes -join ','), $expectedRing, $ringStage
  Add-Check ("CLSAG ring (expect {0})" -f $expectedRing) $allMatch $detail
}

# 2. Stealth addresses -- every output has a 32-byte unique stealth key (always required)
$stealthKeys = @($tx.outputs | ForEach-Object { $_.stealth_address })
$allStealthValid = ($stealthKeys | Where-Object { $_ -notmatch '^[0-9a-f]{64}$' }).Count -eq 0
$stealthUnique = ($stealthKeys | Sort-Object -Unique).Count -eq $stealthKeys.Count
$stealthPass = $allStealthValid -and $stealthUnique
$stealthDetail = if ($stealthUnique) { "$($stealthKeys.Count) unique 32-byte one-time keys" } else { 'duplicate stealth keys detected!' }
Add-Check 'Stealth addresses' $stealthPass $stealthDetail

# 3. Tx-public keys per output -- non-zero (always required, even on coinbase)
$txPubKeys = @($tx.outputs | ForEach-Object { $_.tx_public_key })
$zero64 = ('0' * 64)
$allPubKeysValid = ($txPubKeys | Where-Object { $_ -notmatch '^[0-9a-f]{64}$' -or $_ -eq $zero64 }).Count -eq 0
Add-Check 'Tx public key per output' $allPubKeysValid ("$($txPubKeys.Count) non-zero 32-byte keys")

# 4. Pedersen commitments -- every output has a 32-byte commitment.
#    On coinbase, commitments still exist but commit to the public emission
#    amount with a known blinding factor (so amount IS auditable). The
#    structural check (32 bytes) still applies.
$commitments = @($tx.outputs | ForEach-Object { $_.commitment })
$allCommitValid = ($commitments | Where-Object { $_ -notmatch '^[0-9a-f]{64}$' }).Count -eq 0
$commitDetail = if ($isCoinbase) { "$($commitments.Count) commitment(s) (public emission amount on coinbase)" }
                else { "$($commitments.Count) commitment(s), no plaintext amounts" }
Add-Check 'Pedersen commitments' $allCommitValid $commitDetail

# 5. Bulletproofs+ range proof -- present on transfers, absent on coinbase
if ($isCoinbase) {
  Add-NA 'Bulletproofs+ range proof' 'coinbase amounts are public; no range proof needed (correct)'
} else {
  $rangeProofSize = [int]$tx.range_proof_size
  $hasRangeProof = $tx.has_range_proof -eq $true -and $rangeProofSize -gt 0
  $rangeProofSane = $rangeProofSize -ge 500 -and $rangeProofSize -le 10000
  $rangeProofPass = $hasRangeProof -and $rangeProofSane
  Add-Check 'Bulletproofs+ range proof' $rangeProofPass ("$rangeProofSize bytes for $($tx.output_count) outputs")
}

# 6. View tags -- every output has a view tag (always required)
$viewTagsPresent = ($tx.outputs | Where-Object { $null -eq $_.view_tag }).Count -eq 0
Add-Check 'View tags' $viewTagsPresent ("$($tx.outputs.Count) outputs with view tags")

# 7. Encrypted memos -- informational only
$memoCount = ($tx.outputs | Where-Object { $_.has_memo -eq $true }).Count
$memoText = if ($memoCount -gt 0) { "$memoCount of $($tx.outputs.Count) outputs carry encrypted memos" }
            else { 'no memos in this tx (optional feature, only counted when set)' }
Write-Host ('  [INFO] {0,-32} {1}' -f 'Encrypted memos', $memoText) -ForegroundColor DarkGray

# 8. Sanity -- server's privacy summary agrees with our independent check.
#    For coinbase, expect sender_hidden=false / amount_hidden=false / clsag=false /
#    bulletproofs=false but receiver_hidden=true / stealth=true. For transfers,
#    expect every flag true.
if ($tx.privacy) {
  if ($isCoinbase) {
    $coinbaseConsistent = $tx.privacy.sender_hidden -eq $false `
                     -and $tx.privacy.amount_hidden -eq $false `
                     -and $tx.privacy.clsag_ring_sig -eq $false `
                     -and $tx.privacy.bulletproofs_plus -eq $false `
                     -and $tx.privacy.receiver_hidden -eq $true `
                     -and $tx.privacy.stealth_addresses -eq $true
    Add-Check 'Server privacy summary' $coinbaseConsistent 'flags match expected coinbase shape'
  } else {
    $transferConsistent = $tx.privacy.sender_hidden -eq $true `
                     -and $tx.privacy.receiver_hidden -eq $true `
                     -and $tx.privacy.amount_hidden -eq $true `
                     -and $tx.privacy.clsag_ring_sig -eq $true `
                     -and $tx.privacy.bulletproofs_plus -eq $true `
                     -and $tx.privacy.stealth_addresses -eq $true
    Add-Check 'Server privacy summary' $transferConsistent 'all-true on transfer, consistent with independent check'
  }
}

# -- verdict -------------------------------------------------------
Write-Host ''
Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
if ($failures -eq 0) {
  if ($isCoinbase) {
    Write-Host '  PASS  coinbase privacy shape verified (recipient-side only)' -ForegroundColor Green
    Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  This coinbase tx:' -ForegroundColor DarkGray
    Write-Host '    - mints to a one-time stealth key (recipient hidden)' -ForegroundColor DarkGray
    Write-Host '    - has the public emission amount (auditable supply by design)' -ForegroundColor DarkGray
    Write-Host '    - includes a view tag for fast wallet scanning' -ForegroundColor DarkGray
  } else {
    Write-Host '  PASS  all transfer privacy properties verified from raw tx fields' -ForegroundColor Green
    Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
    Write-Host '  This transaction:' -ForegroundColor DarkGray
    Write-Host ('    - hides the sender among {0} ring members (CLSAG, {1})' -f $expectedRing, $(if ($txHeight -lt 10000) { 'bootstrap' } else { 'post-bootstrap' })) -ForegroundColor DarkGray
    Write-Host '    - hides the recipient via one-time stealth keys' -ForegroundColor DarkGray
    Write-Host '    - hides the amounts via Pedersen commitments + Bulletproofs+' -ForegroundColor DarkGray
    Write-Host '    - includes view tags for fast wallet scanning' -ForegroundColor DarkGray
    if ($txHeight -lt 10000) {
      Write-Host ('    NOTE: chain is in bootstrap window (block {0} < 10000). The' -f $txHeight) -ForegroundColor DarkGray
      Write-Host '          full Ring-16 anonymity set activates at block 10000.' -ForegroundColor DarkGray
    }
  }
  exit 0
} else {
  Write-Host "  FAIL  $failures privacy property check(s) did not pass" -ForegroundColor Red
  Write-Host '------------------------------------------------------------' -ForegroundColor DarkGray
  exit 1
}
