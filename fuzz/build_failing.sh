#!/bin/bash
# Full cargo fuzz build (with ASAN+sancov) on the 6 previously-failing targets,
# to confirm they actually link and not just typecheck.
set -u

cd "$(dirname "$0")"

TARGETS=(fuzz_mnemonic fuzz_lelantus_spark fuzz_disclosure fuzz_fee_market fuzz_rpc_body fuzz_framing)

PASS=0
FAIL=0
FAILS=()
for t in "${TARGETS[@]}"; do
  printf '===== %s ===== ' "$t"
  if cargo +nightly fuzz build "$t" >/tmp/fuzz_build_${t}.log 2>&1; then
    echo OK
    PASS=$((PASS+1))
  else
    echo FAIL
    FAIL=$((FAIL+1))
    FAILS+=("$t")
    tail -30 /tmp/fuzz_build_${t}.log | sed 's/^/    /'
  fi
done

echo "================================="
echo "Result: $PASS pass, $FAIL fail"
if [ "$FAIL" -gt 0 ]; then
  echo "Failed: ${FAILS[*]}"
  exit 1
fi
