#!/usr/bin/env bash
# CoinCync — easy launcher (Linux/macOS).  Run:  ./scripts/start-coincync.sh
# Pick a number to run a node, mine, or make a wallet. No flags to remember.
set -u

NETWORK="testnet"
SEED="2.29.34.197:28080"                 # public testnet seed peer
DATADIR="$HOME/.coincync"
WALLET="$HOME/.coincync/wallets/default.wallet"

# Easy launcher uses an UNENCRYPTED wallet so nothing ever asks for a password.
export COINCYNC_WALLET_PASSWORD=""

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
find_exe() {
  for d in "$here" "$here/.." "$here/../target/release" "$here/../target/debug"; do
    [ -x "$d/$1" ] && { echo "$d/$1"; return; }
  done
  command -v "$1" 2>/dev/null
}
NODE="$(find_exe coincync-node)"
WALLET_EXE="$(find_exe coincync-wallet)"

banner() {
  clear
  echo
  echo "   ===================================================="
  echo "      CoinCync  -  easy launcher"
  echo "   ===================================================="
  echo "      network : $NETWORK"
  echo "      node    : $([ -n "$NODE" ] && echo found || echo 'NOT FOUND')"
  echo "      data    : $DATADIR"
  echo
}

get_address() {
  [ -n "$WALLET_EXE" ] || { echo ""; return; }
  if [ ! -f "$WALLET" ]; then
    echo "No wallet yet - creating one (unencrypted, for easy mining)..." >&2
    "$WALLET_EXE" --wallet "$WALLET" --network "$NETWORK" create --no-encrypt >&2
  fi
  "$WALLET_EXE" --wallet "$WALLET" --network "$NETWORK" address --json 2>/dev/null \
    | sed -n 's/.*"address"[^"]*"\([^"]*\)".*/\1/p' | head -1
}

run_node() {
  local mine="$1"; banner
  local args=(--network "$NETWORK" --data-dir "$DATADIR" --addnode "$SEED")
  [ -n "$mine" ] && { args+=(--mine "$mine"); echo "Mining to: $mine"; }
  echo "Starting the node. Leave this open; Ctrl+C to stop."; echo
  "$NODE" "${args[@]}"
  echo; read -rp "Node stopped. Press Enter"
}

while true; do
  banner
  echo "   What would you like to do?"; echo
  echo "     [1]  Run a node   (join the network)"
  echo "     [2]  Run a node AND mine   (earn CYNC)"
  echo "     [3]  Create / show my wallet"
  echo "     [4]  Check my balance"
  echo "     [q]  Quit"; echo
  read -rp "   Type a number and press Enter: " c
  case "$c" in
    1) [ -n "$NODE" ] && run_node "" || { echo "coincync-node not found"; read -r; } ;;
    2) if [ -n "$NODE" ]; then a="$(get_address)"; [ -n "$a" ] && run_node "$a" || { echo "no address"; read -r; }; else echo "coincync-node not found"; read -r; fi ;;
    3) [ -n "$WALLET_EXE" ] && { [ -f "$WALLET" ] || "$WALLET_EXE" --wallet "$WALLET" --network "$NETWORK" create --no-encrypt; "$WALLET_EXE" --wallet "$WALLET" --network "$NETWORK" address; }; read -rp "Press Enter" ;;
    4) [ -n "$WALLET_EXE" ] && "$WALLET_EXE" --wallet "$WALLET" --network "$NETWORK" balance; read -rp "Press Enter" ;;
    q|Q) break ;;
  esac
done
