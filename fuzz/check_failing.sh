#!/bin/bash
# Quick cargo check on the 6 fuzz targets that failed the smoke.
set -u

cd "$(dirname "$0")"

TARGETS=(fuzz_mnemonic fuzz_lelantus_spark fuzz_disclosure fuzz_fee_market fuzz_rpc_body fuzz_framing)

for t in "${TARGETS[@]}"; do
  echo "===== $t ====="
  cargo +nightly check --release --bin "$t" 2>&1 | grep -E '^(error|warning: unused|  --> |  *[0-9]+ \| )' | head -80
done
