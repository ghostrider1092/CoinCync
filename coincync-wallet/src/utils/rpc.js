// CoinCync Wallet RPC
//
// Strategy: Require the Tauri backend for authoritative wallet state/actions.
// Never fabricate wallet success/funds/addresses in the UI.
// RULE: Never show transactions or balances that didn't come from the wallet's
// own view-key scan. Mixing chain-wide data with wallet data is a privacy leak.

let _scanning = false;

/** True only inside the Tauri desktop shell (`npx tauri dev` / packaged app). Plain browser tabs on :1420 are false. */
export function isWalletBackendAvailable() {
  return typeof window !== "undefined" && !!window.__TAURI__;
}

function asErrorMessage(e) {
  if (typeof e === "string") return e;
  return e?.message || String(e);
}

function extractErrorCode(msg) {
  const m = String(msg || "").match(/^\[([A-Z0-9_]+)\]\s*/);
  return m ? m[1] : null;
}

export function formatWalletError(e, fallback = "Wallet request failed") {
  const raw = asErrorMessage(e);
  const code = extractErrorCode(raw);
  switch (code) {
    case "AUTH_INVALID_PASSWORD":
      return "Incorrect password.";
    case "AUTH_RATE_LIMITED":
      return raw.replace(/^\[[A-Z0-9_]+\]\s*/, "");
    case "WALLET_NOT_FOUND":
      return "Wallet file not found. Restore with your seed phrase.";
    case "WALLET_INVALID_SEED":
      return "Seed phrase is invalid. Check spacing and spelling of each word.";
    case "WALLET_SEED_PARSE_FAILED":
      return "Wallet created, but seed phrase could not be displayed safely. Try again and keep the terminal open.";
    case "WALLET_LOCKED":
      return "Wallet is locked. Unlock first.";
    case "WALLET_SESSION_MISSING":
      return "Wallet session expired. Unlock again.";
    default:
      return raw || fallback;
  }
}

// Require Tauri invoke and propagate real backend failures.
async function tauri(cmd, args={}) {
  if (!isWalletBackendAvailable()) {
    throw new Error(
      "Wallet backend unavailable — open this app with the CoinCync Wallet desktop window (run: npx tauri dev from coincync-wallet). " +
        "A normal browser tab at localhost:1420 has no Rust backend."
    );
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

  // Update check — Monero posture, user-invoked only. Backend gates
  // the GitHub HTTPS request behind this call; the frontend gates this
  // call behind the Settings `checkUpdates` toggle (default OFF).
  checkForUpdate: async () => tauri("check_for_update"),
};
