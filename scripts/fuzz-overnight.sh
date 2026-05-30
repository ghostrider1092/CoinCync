#!/usr/bin/env bash
# scripts/fuzz-overnight.sh
#
# Sequential 8-hour fuzz pass across every target. Each target gets full
# CPU for 80 minutes, runs from its existing corpus (warm), saves any
# crashes + corpus growth, and contributes a per-target row to the final
# summary report.
#
# Run from inside WSL Ubuntu (where ASAN-instrumented fuzz actually
# links — see scripts/fuzz-wsl-setup.md for one-time setup).
#
# Usage:
#   nohup bash scripts/fuzz-overnight.sh > ~/fuzz-overnight.log 2>&1 &
#   tail -f ~/fuzz-overnight.log
#
# Output:
#   ~/coincync-fuzz/fuzz/corpus/<target>/      grows with discovered inputs
#   ~/coincync-fuzz/fuzz/artifacts/<target>/   any crashes (review + triage)
#   ~/fuzz-overnight-report.txt                final summary table

set -u  # don't `-e` — we want to keep running even if one target crashes

cd ~/coincync-fuzz/fuzz || { echo "fatal: ~/coincync-fuzz/fuzz not found — run scripts/fuzz-wsl-setup.sh first" >&2; exit 2; }
# shellcheck source=/dev/null  # path is operator HOME, not in this repo
source "$HOME/.cargo/env"

PER_TARGET_SECS="${PER_TARGET_SECS:-1200}"  # 20 min × 27 targets = 9 hr pure-fuzz + compile
REPORT="$HOME/fuzz-overnight-report.txt"

TARGETS=(
  # Network / wire
  fuzz_p2p_message    # P2P wire-frame + every typed-message borsh decode
  fuzz_framing        # MessageHeader-only validation path
  # Consensus
  fuzz_block          # block-level borsh decode
  fuzz_transaction    # tx-level borsh decode
  fuzz_pow_hash       # PoW + RandomX FFI (the only unsafe boundary)
  fuzz_difficulty     # DAA arithmetic edge cases
  fuzz_rolling_finality # Ed25519 checkpoint verification
  fuzz_fee_market     # fee market construction
  # Crypto primitives
  fuzz_clsag          # CLSAG ring signature parse + verify
  fuzz_stealth        # stealth-address output scanning
  fuzz_bulletproofs   # range-proof byte parsing
  fuzz_orchard        # orchard shielded-pool key tree + note + nullifier
  fuzz_dleq           # strict-binding DLEQ proof (cyncswap)
  fuzz_adaptor_sig    # cyncswap adaptor-secret parsing
  fuzz_memo_decrypt   # encrypted memo decryption
  fuzz_view_key_scope # scoped view key derivation (privacy innov #3)
  fuzz_mw_cutthrough  # MimbleWimble kernel-set verification
  fuzz_lelantus_spark # Spark spend verification (CIP-005)
  fuzz_disclosure     # selective-disclosure proof verification
  fuzz_kernel_offset  # MW kernel offset arithmetic
  fuzz_batch_verify   # batch signature verification
  # Wallet / persistence
  fuzz_mnemonic       # BIP-39 mnemonic parsing
  fuzz_address        # bech32 address parse
  fuzz_state_file     # cyncswap state-file deserialization (with HMAC)
  fuzz_wallet_persistence # main wallet file deserialization
  # API
  fuzz_rpc_body       # JSON-RPC body deserialization
  # Primitive
  fuzz_hash_primitive # Hash::from_bytes universal type
)

START_ISO="$(date -u +%FT%TZ)"
{
  echo "==============================================================="
  echo "  CoinCync overnight fuzz pass"
  echo "==============================================================="
  echo "  started:        $START_ISO"
  echo "  per-target:     ${PER_TARGET_SECS}s ($((PER_TARGET_SECS / 60)) min)"
  echo "  targets:        ${#TARGETS[@]}"
  echo "  total budget:   $((${#TARGETS[@]} * PER_TARGET_SECS / 60)) min"
  echo "  ASAN:           enabled (Linux compiler-rt)"
  echo "  output:         $REPORT"
  echo "==============================================================="
} | tee "$REPORT"

for target in "${TARGETS[@]}"; do
  echo
  echo "==============================================================="
  echo "  $target  ($(date -u +%FT%TZ))"
  echo "==============================================================="

  # Crash count BEFORE this run, to count incremental
  ART_DIR="artifacts/$target"
  CRASHES_BEFORE=0
  if [[ -d "$ART_DIR" ]]; then
    CRASHES_BEFORE=$(find "$ART_DIR" -type f | wc -l)
  fi

  # Corpus count BEFORE
  CORPUS_DIR="corpus/$target"
  CORPUS_BEFORE=0
  if [[ -d "$CORPUS_DIR" ]]; then
    CORPUS_BEFORE=$(find "$CORPUS_DIR" -type f | wc -l)
  fi

  # Run. cargo +nightly fuzz run exits 0 on success, 77 on crash found.
  # We capture both; libFuzzer also leaves crash files in artifacts/.
  RUN_RC=0
  cargo +nightly fuzz run "$target" -- \
        -max_total_time="$PER_TARGET_SECS" \
        -print_final_stats=1 \
        2>&1 | tail -8 || RUN_RC=$?

  # Crash count AFTER
  CRASHES_AFTER=0
  if [[ -d "$ART_DIR" ]]; then
    CRASHES_AFTER=$(find "$ART_DIR" -type f | wc -l)
  fi
  CRASHES_NEW=$((CRASHES_AFTER - CRASHES_BEFORE))

  CORPUS_AFTER=0
  if [[ -d "$CORPUS_DIR" ]]; then
    CORPUS_AFTER=$(find "$CORPUS_DIR" -type f | wc -l)
  fi
  CORPUS_NEW=$((CORPUS_AFTER - CORPUS_BEFORE))

  STATUS=$([ $CRASHES_NEW -gt 0 ] && echo "CRASHES_FOUND" || echo "CLEAN")
  printf "  %-22s exit=%d  crashes=+%-3d corpus=+%-4d  [%s]\n" \
         "$target" "$RUN_RC" "$CRASHES_NEW" "$CORPUS_NEW" "$STATUS" \
         | tee -a "$REPORT"
done

END_ISO="$(date -u +%FT%TZ)"
{
  echo
  echo "==============================================================="
  echo "  overnight pass complete"
  echo "==============================================================="
  echo "  started:        $START_ISO"
  echo "  finished:       $END_ISO"
  echo
  echo "  Final corpus + crashes:"
  for d in corpus/*/; do
    name=$(basename "$d")
    n=$(find "$d" -type f 2>/dev/null | wc -l)
    s=$(du -sh "$d" 2>/dev/null | cut -f1)
    printf "    %-22s %5d files  %s\n" "$name" "$n" "$s"
  done
  echo
  # Classify artifacts properly. libFuzzer drops files in artifacts/
  # for FOUR distinct reasons, only ONE of which is a real crash:
  #   crash-*       => actual panic / assertion / SIGSEGV (real bug)
  #   slow-unit-*   => input executed slowly (perf, not a bug)
  #   oom-*         => libFuzzer's malloc tripped its alloc limit
  #                    (resource-budget hit, not necessarily a bug)
  #   timeout-*     => single-input wall-clock budget hit (often
  #                    benign on slow CI hardware)
  # Earlier versions of this report lumped all four under "CRASH
  # FILES" and triggered triage panic on benign artifacts. Split.
  for d in artifacts/*/; do
    name=$(basename "$d")
    real=$(find "$d" -type f -name 'crash-*' 2>/dev/null | wc -l)
    slow=$(find "$d" -type f -name 'slow-unit-*' 2>/dev/null | wc -l)
    oom=$(find  "$d" -type f -name 'oom-*' 2>/dev/null | wc -l)
    timeout=$(find "$d" -type f -name 'timeout-*' 2>/dev/null | wc -l)
    if [[ $real -gt 0 ]]; then
      printf "    %-22s %5d REAL crash(es) — triage: cargo +nightly fuzz tmin %s <crash-file>\n" \
             "$name" "$real" "$name"
    fi
    if [[ $slow -gt 0 || $oom -gt 0 || $timeout -gt 0 ]]; then
      printf "    %-22s perf artifacts: %d slow, %d oom, %d timeout (NOT bugs unless investigating perf)\n" \
             "$name" "$slow" "$oom" "$timeout"
    fi
  done
} | tee -a "$REPORT"
