# cov.ps1 — one-liner for the section-coverage tool (PowerShell).
#
#   .\cov.ps1 distribute_fee        # query a section/test/tag → run + color
#   .\cov.ps1 C-2                   # by incident tag
#   .\cov.ps1 fee_market.rs:5       # a file's section 5
#   .\cov.ps1 --gaps               # not-green sections, critical first
#   .\cov.ps1 --lint               # unmapped public fns
#   .\cov.ps1 --check              # CI gate (exit code)
#   .\cov.ps1                      # whole-codebase report
#
# It sets the env, finds the tool + lib_test.log automatically, and (for a
# query) uses the cached log so lookups are instant. Capture the log first with:
#   cargo test --lib --features testnet | Tee-Object lib_test.log
param([Parameter(ValueFromRemainingArguments = $true)] [string[]] $Args)

$env:LIBCLANG_PATH = "C:\Program Files\LLVM\bin"
$env:COINCYNC_RANDOMX_LIGHT_MODE = "1"
$env:RUST_MIN_STACK = "268435456"

$repo = Split-Path -Parent $MyInvocation.MyCommand.Path
$tool = Join-Path $repo "docs\audit\tools\build_section_heatmap.py"
$log  = Join-Path $repo "lib_test.log"
$logArgs = @()
if (Test-Path $log) { $logArgs = @("--test-log", $log) }

if ($Args.Count -ge 1 -and $Args[0] -notlike '-*') {
    # first token is a query term (section/test/tag)
    $q = $Args[0]
    $rest = @()
    if ($Args.Count -gt 1) { $rest = $Args[1..($Args.Count - 1)] }
    python $tool --query $q --no-run @logArgs @rest
}
else {
    # a flag/mode, or nothing → full report
    python $tool @logArgs @Args
}
