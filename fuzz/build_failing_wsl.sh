#!/bin/bash
# Build the 6 newly-fixed targets inside the WSL local fuzz copy
# (where the overnight script runs). Confirms the TOML fix carries
# into the overnight environment.
set -u

cd ~/coincync-fuzz/fuzz

TARGETS=(fuzz_mnemonic fuzz_lelantus_spark fuzz_disclosure fuzz_fee_market fuzz_rpc_body fuzz_framing)

PASS=0; FAIL=0; FAILS=()
for t in "${TARGETS[@]}"; do
  printf '===== %s ===== ' "$t"
  if cargo +nightly fuzz build "$t" >/tmp/wsl_fuzz_build_${t}.log 2>&1; then
    echo OK
    PASS=$((PASS+1))
  else
    echo FAIL
    FAIL=$((FAIL+1))
    FAILS+=("$t")
    tail -25 /tmp/wsl_fuzz_build_${t}.log | sed 's/^/    /'
  fi
done

echo "================================="
echo "WSL-local result: $PASS pass, $FAIL fail"
if [ "$FAIL" -gt 0 ]; then
  echo "Failed: ${FAILS[*]}"
  exit 1
fi
