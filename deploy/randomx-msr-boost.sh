#!/usr/bin/env bash
# randomx-msr-boost.sh — apply the documented RandomX MSR tweaks for AMD Zen,
# the "RandomX boost" that mature miners (XMRig) use. It writes a handful of
# model-specific registers that relax the hardware prefetcher / cache behaviour
# RandomX fights with, for ~5–15% more hashrate on AMD. CPU-only; it does NOT
# touch CoinCync consensus, the miner binary, or the chain — it tunes the host.
#
# Scope: full-mem miner boxes with an AMD Zen CPU. No-op (and refuses) on
# anything it doesn't recognise. Intel has no equivalent preset here.
#
# Usage:
#   sudo bash deploy/randomx-msr-boost.sh apply     # apply the preset now
#   sudo bash deploy/randomx-msr-boost.sh status    # show CPU + current MSRs
#   sudo bash deploy/randomx-msr-boost.sh revert     # restore via reboot note
#
# Persistence: MSR writes do NOT survive a reboot. Install the companion
# oneshot unit (deploy/coincync-randomx-msr.service) so they reapply at boot
# before the miner starts. A plain reboot with the unit disabled fully reverts.
#
# Safety: applies ONLY the published preset for a recognised Zen generation;
# refuses unknown CPUs rather than guess. Values are XMRig's documented
# randomx_boost presets — not invented here.
set -uo pipefail

need_root() { [ "$(id -u)" -eq 0 ] || { echo "must run as root (needs wrmsr)"; exit 1; }; }

have_wrmsr() {
  command -v wrmsr >/dev/null 2>&1 || {
    echo "wrmsr not found — install msr-tools:  sudo apt-get install -y msr-tools"
    exit 1
  }
}

# Echo the Zen generation we recognise, or empty for "unsupported".
detect_zen() {
  local vendor family model
  vendor=$(awk -F': ' '/vendor_id/{print $2; exit}' /proc/cpuinfo)
  family=$(awk -F': ' '/cpu family/{print $2; exit}' /proc/cpuinfo)
  model=$(awk -F': ' '/^model\b/{print $2; exit}' /proc/cpuinfo)
  [ "$vendor" = "AuthenticAMD" ] || { echo ""; return; }
  case "$family" in
    23) echo "zen2" ;;                       # family 0x17 = Zen / Zen+ / Zen2
    25) if [ "${model:-0}" -ge 16 ] 2>/dev/null; then echo "zen4"; else echo "zen3"; fi ;;  # 0x19
    26) echo "zen5" ;;                        # family 0x1A
    *)  echo "" ;;
  esac
}

apply_preset() {
  local gen="$1"
  case "$gen" in
    zen2)
      # XMRig randomx_boost, Zen/Zen+/Zen2 preset.
      wrmsr -a 0xc0011020 0x0            && \
      wrmsr -a 0xc0011021 0x40           && \
      wrmsr -a 0xc0011022 0x1510000      && \
      wrmsr -a 0xc001102b 0x2000cc16
      ;;
    zen3|zen4|zen5)
      # XMRig randomx_boost, Zen3+ preset (same across Zen3/4/5 in XMRig).
      wrmsr -a 0xc0011020 0x4480000000000 && \
      wrmsr -a 0xc0011021 0x1c000200000040 && \
      wrmsr -a 0xc0011022 0xc000000401570000 && \
      wrmsr -a 0xc001102b 0x2000cc10
      ;;
    *) return 2 ;;
  esac
}

cmd="${1:-apply}"
case "$cmd" in
  apply)
    need_root; have_wrmsr
    modprobe msr 2>/dev/null || true
    gen=$(detect_zen)
    if [ -z "$gen" ]; then
      echo "CPU not a recognised AMD Zen generation — refusing to write MSRs (no-op)."
      echo "  vendor/family/model: $(awk -F': ' '/vendor_id|cpu family|^model\b/{printf "%s ", $2}' /proc/cpuinfo)"
      exit 0
    fi
    echo "Detected AMD $gen — applying RandomX boost MSR preset..."
    if apply_preset "$gen"; then
      echo "OK: MSR preset applied ($gen). Re-run the miner (or it inherits on next hash epoch)."
    else
      echo "FAILED to write one or more MSRs (kernel lockdown? secure boot?). Hashrate unaffected, just not boosted."
      exit 1
    fi
    ;;
  status)
    gen=$(detect_zen); echo "zen generation: ${gen:-unsupported}"
    if command -v rdmsr >/dev/null 2>&1 && [ "$(id -u)" -eq 0 ]; then
      modprobe msr 2>/dev/null || true
      for r in 0xc0011020 0xc0011021 0xc0011022 0xc001102b; do
        printf "  %s = 0x%s\n" "$r" "$(rdmsr -p0 "$r" 2>/dev/null || echo '?')"
      done
    else
      echo "  (run as root with msr-tools for live MSR values)"
    fi
    ;;
  revert)
    echo "MSR writes do not persist across a reboot. To revert:"
    echo "  1) disable the boot unit:  systemctl disable coincync-randomx-msr.service"
    echo "  2) reboot — defaults are restored by the firmware."
    ;;
  *)
    echo "usage: $0 {apply|status|revert}"; exit 64 ;;
esac
