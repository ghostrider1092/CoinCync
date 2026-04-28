// CoinCync Wallet RPC
//
// Strategy: Require the Tauri backend for authoritative wallet state/actions.
// Never fabricate wallet success/funds/addresses in the UI.
// RULE: Never show transactions or balances that didn't come from the wallet's
// own view-key scan. Mixing chain-wide data with wallet data is a privacy leak.

let _scanning = false;

function asErrorMessage(e) {
  if (typeof e === "string") return e;
  return e?.message || String(e);
}

// Require Tauri invoke and propagate real backend failures.
async function tauri(cmd, args={}) {
  if (!window.__TAURI__) {
    throw new Error("Wallet backend unavailable (not running in Tauri)");
  }
  try {
    const { invoke } = await import("@tauri-apps/api/tauri");
    return await invoke(cmd, args);
  } catch (e) {
    const msg = asErrorMessage(e);
    console.warn(`[RPC] ${cmd} failed:`, msg);
    throw new Error(msg);
  }
}

export const rpc = {

  getBalance: async () => tauri("get_balance"),

  getBlockHeight: async () => tauri("get_block_height"),

  getPeerCount: async () => tauri("get_peer_count"),

  getTransactions: async () => tauri("get_transactions"),

  getFeeEstimate: async () => tauri("get_fee_estimate"),

  getRsaState: async () => tauri("get_rsa_state"),

  getNetworkInfo: async () => tauri("get_network_info"),

  validateAddress: async (addr) => tauri("validate_address", { address: addr }),

  sendTransaction: async (params) => tauri("send_transaction", params),

  // Wallet lifecycle
  createWallet: async (password) => tauri("create_wallet", { password }),
  restoreWallet: async (seed, password) => tauri("restore_wallet", { seed, password }),

  unlockWallet: async (password) => tauri("unlock_wallet", { password }),
  lockWallet: async () => tauri("lock_wallet"),

  scanWallet: async () => {
    _scanning = true;
    try {
      return await tauri("scan_wallet");
    } finally {
      _scanning = false;
    }
  },

  // Mining
  startMining: async (address, threads) => tauri("start_mining", { address, threads }),

  stopMining: async () => tauri("stop_mining"),

  getMiningStats: async () => tauri("get_mining_stats"),

  checkBinaries: async () => tauri("check_binaries"),

  getWalletAddress: async () => tauri("get_wallet_address"),
};
