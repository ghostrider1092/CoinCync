/* ─── CoinCync v2 wallet — entrypoint ─────────────────────────────
 *
 * Vanilla JS frontend. Loads inside Tauri 1.6 (desktop binary) OR
 * standalone in a browser (design preview). The `invoke()` wrapper
 * below routes calls to real Tauri commands when running native,
 * and to mock responses when running in a plain browser.
 */

const app = document.getElementById("app");

// ─── Tauri invoke wrapper ─────────────────────────────────────────
// Tauri 1.x exposes the bridge as window.__TAURI__.tauri.invoke().
// In a plain browser preview, that's undefined and we mock responses
// so the design preview still works without the backend.

const IS_TAURI = typeof window !== "undefined" && !!window.__TAURI__;

async function invoke(cmd, params = undefined) {
  if (IS_TAURI) {
    const t = window.__TAURI__;
    // Resolve invoke across Tauri versions. v2 (post-migration) exposes it at
    // window.__TAURI__.core.invoke; v1 used window.__TAURI__.invoke or
    // window.__TAURI__.tauri.invoke. Prefer v2, fall back to v1 so the same
    // frontend works either way.
    const inv =
      (t.core && t.core.invoke) || (t.tauri && t.tauri.invoke) || t.invoke;
    if (typeof inv !== "function") {
      console.error("[invoke] no invoke() on window.__TAURI__:", Object.keys(t));
      throw new Error("Tauri API not initialised");
    }
    try {
      return await inv(cmd, params);
    } catch (e) {
      console.warn(`[invoke ${cmd}] failed:`, e);
      throw e;
    }
  }
  return await mockInvoke(cmd, params);
}

async function mockInvoke(cmd, params) {
  // Canned responses so the browser preview shows realistic data.
  switch (cmd) {
    case "unlock_wallet":
      // Mock: any 4+ char password succeeds, except "wrong".
      if (!params || !params.password) return false;
      if (params.password === "wrong") return false;
      return params.password.length >= 4;

    case "get_balance":
      return { total: "12.847213", unlocked: "12.847213", locked: "0.000000" };

    case "get_block_height":
      return { height: 524113, chainHeight: 524113, syncPct: 100 };

    case "get_peer_count":
      return { peers: 8 };

    case "get_transactions":
      return { txs: [] };

    case "get_wallet_address":
      return "tCYNCxq8a4f1m12k7q4j5n2p3v9w6r4b2t8c1z0";

    case "get_mining_stats":
      return { is_mining: mining.on, hashrate: mining.hashrate, blocks_found: 3, threads: mining.threads, algorithm: "RandomX" };

    case "swap_list":
      return { swaps: [] };

    case "generate_qr_svg": {
      // Browser-preview fallback (no Tauri = no qrcode crate). Returns
      // a decorative-grid SVG that LOOKS like a QR for design purposes.
      // The real Tauri build returns a scannable code via the workspace's
      // qrcode crate.
      const payload = (params && params.payload) || "";
      const seed = [...payload].reduce((a, c) => a * 31 + c.charCodeAt(0), 0);
      const size = 25;
      const cells = [];
      let s = Math.abs(seed);
      for (let y = 0; y < size; y++) {
        for (let x = 0; x < size; x++) {
          const inCorner =
            (x < 7 && y < 7) || (x >= size - 7 && y < 7) || (x < 7 && y >= size - 7);
          const inCornerInner =
            (x >= 1 && x < 6 && y >= 1 && y < 6) ||
            (x >= size - 6 && x < size - 1 && y >= 1 && y < 6) ||
            (x >= 1 && x < 6 && y >= size - 6 && y < size - 1);
          const inCornerInnerInner =
            (x >= 2 && x < 5 && y >= 2 && y < 5) ||
            (x >= size - 5 && x < size - 2 && y >= 2 && y < 5) ||
            (x >= 2 && x < 5 && y >= size - 5 && y < size - 2);
          let dark;
          if (inCorner && !inCornerInner) dark = true;
          else if (inCorner && inCornerInner && !inCornerInnerInner) dark = false;
          else if (inCorner && inCornerInnerInner) dark = true;
          else { s = (s * 1103515245 + 12345) >>> 0; dark = (s & 1) === 1; }
          if (dark) cells.push(`<rect x="${x}" y="${y}" width="1" height="1" fill="#0a0a0a"/>`);
        }
      }
      return `<svg viewBox="0 0 ${size} ${size}" xmlns="http://www.w3.org/2000/svg">${cells.join("")}</svg>`;
    }

    default:
      console.warn(`[mock] no canned response for "${cmd}"`);
      return null;
  }
}

// ─── Logo (inline SVG, scales infinitely / sharp at 4K) ───────────
//
// The CoinCync face: a thick gold ring forms the head, an arc-cutout
// shapes an open mouth on the right side, and two gold dots inside
// are the eyes. Same mark as website/assets/favicon.svg and
// website/assets/logo-mark.svg — kept in lock-step here so the
// wallet's splash / unlock / sidebar logos match the favicon + the
// website brand. Coordinates scaled 2× to fit the 100×100 viewBox the
// rest of the splash chrome (glow halos, sizing) was tuned for.
const LOGO_SVG = `
  <svg viewBox="0 0 100 100" fill="none" xmlns="http://www.w3.org/2000/svg" aria-label="CoinCync">
    <!-- Gold ring forming the face perimeter -->
    <circle cx="50" cy="50" r="39" fill="none" stroke="url(#cc-ring)" stroke-width="7"/>
    <!-- Mouth: arc cutout on the right side. Drawn with the inner-fill
         color so it "erases" most of the ring, leaving only the small
         right-facing opening that gives the face its character. -->
    <path d="M 84 50 A 34 34 0 1 0 50 84" fill="none" stroke="url(#cc-inner)" stroke-width="11"/>
    <line x1="81" y1="50" x2="89" y2="50" stroke="url(#cc-inner)" stroke-width="11"/>
    <!-- Eyes -->
    <circle cx="34" cy="50" r="4" fill="url(#cc-dot)"/>
    <circle cx="66" cy="50" r="4" fill="url(#cc-dot)"/>
    <defs>
      <linearGradient id="cc-ring" x1="0" y1="0" x2="100" y2="100" gradientUnits="userSpaceOnUse">
        <stop offset="0%"   stop-color="#f5cf7f"/>
        <stop offset="100%" stop-color="#b8854a"/>
      </linearGradient>
      <linearGradient id="cc-inner" gradientUnits="userSpaceOnUse">
        <stop offset="0%"  stop-color="#0a0a09"/>
        <stop offset="100%" stop-color="#0a0a09"/>
      </linearGradient>
      <radialGradient id="cc-dot">
        <stop offset="0%"   stop-color="#fff"/>
        <stop offset="100%" stop-color="#d4a059"/>
      </radialGradient>
    </defs>
  </svg>
`;

// ─── Icons (inline SVG, single source) ────────────────────────────
const ICONS = {
  dashboard: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`,
  send:      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>`,
  receive:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>`,
  swap:      `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="17 1 21 5 17 9"/><path d="M3 11V9a4 4 0 0 1 4-4h14"/><polyline points="7 23 3 19 7 15"/><path d="M21 13v2a4 4 0 0 1-4 4H3"/></svg>`,
  history:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v5h5"/><path d="M3.05 13A9 9 0 1 0 6 5.3L3 8"/><polyline points="12 7 12 12 15 14"/></svg>`,
  addresses: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 10c0 7-9 13-9 13s-9-6-9-13a9 9 0 0 1 18 0z"/><circle cx="12" cy="10" r="3"/></svg>`,
  mining:    `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M14 4l6 6-9 9H5v-6z"/><path d="M14 4l3-3 6 6-3 3"/></svg>`,
  multisig:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
  settings:  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
  arrowUp:   `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="19" x2="12" y2="5"/><polyline points="5 12 12 5 19 12"/></svg>`,
  arrowDown: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><polyline points="19 12 12 19 5 12"/></svg>`,
};

// ─── State ────────────────────────────────────────────────────────
//
// Initial state is ZERO / EMPTY across the board — no mock values. The
// chain_state + wallet_state push events populate the real numbers
// once the wallet unlocks and the Rust poller starts emitting. The UI
// renders empty states (illustrated empty card, "Unlock to reveal," etc.)
// when state is empty, so users never see fake mock numbers as if they
// were real wallet data.
//
// Browser-preview mode (no Tauri) populates the same state via mockInvoke
// in primeWalletState — kept for design-demo purposes, never visible in
// the real Tauri-launched wallet.
let state = {
  page: "dashboard",
  // Chain-side (driven by chain_state event)
  blockHeight: 0,
  chainHeight: 0,
  syncPct: 0,
  isSynced: false,
  peerCount: 0,
  mempoolSize: 0,
  connected: false,
  // Network identity (driven by get_network_info at boot). `unit` is the
  // display ticker — testnet builds show tCYNC, mainnet shows CYNC. Default
  // to the testnet unit since testnet is the only live network today.
  network: "",
  unit: "tCYNC",
  nodeVersion: "",
  // Live fee estimate from the node ({slow,normal,fast,flash} as decimal
  // strings). Null until get_fee_estimate resolves; the Send view falls
  // back to static defaults until then.
  feeEstimate: null,
  // Wallet-side (driven by wallet_state event + initial scan)
  balance: 0,            // atomic units → CYNC (already divided)
  balanceUnlocked: 0,    // confirmed + spendable
  scannedHeight: 0,
  utxoCount: 0,
  txCount: 0,
  transactions: [],      // populated by get_transactions invoke
  address: "",           // populated by get_wallet_address invoke
  walletFilePath: "",    // populated by wallet_path invoke (shown in Settings → About)
  // Task #7+#8: reorg-notification state. Null when no reorg has been
  // detected since unlock (or since the user dismissed). Non-null
  // values cause renderShell() to inject the reorg banner above the
  // current page's main content.
  lastReorgAtHeight: null,
  lastReorgDepth: null,
};

// ─── Live chain-state subscription ────────────────────────────────
// Rust spawns a background poller that calls `get_info` every 2s and
// emits a `chain_state` event when anything changes (height, peer count,
// sync status, mempool depth, or connection drops). The UI subscribes
// once at boot and updates reactively — no per-component invoke() polls.
async function subscribeToChainState() {
  if (!IS_TAURI || !window.__TAURI__.event) {
    // Browser-preview mode: synthesize a slow tick so the demo feels alive.
    setInterval(() => {
      state.blockHeight += 1;
      if (state.page === "dashboard") renderShell();
    }, 60_000);
    return;
  }
  try {
    await window.__TAURI__.event.listen("chain_state", (event) => {
      const p = event.payload || {};
      state.connected   = !!p.connected;
      state.blockHeight = p.height ?? state.blockHeight;
      state.chainHeight = p.chain_height ?? state.chainHeight;
      state.syncPct     = (typeof p.sync_pct === "number") ? p.sync_pct : state.syncPct;
      state.isSynced    = !!p.is_synced;
      state.peerCount   = (typeof p.peer_count === "number") ? p.peer_count : state.peerCount;
      state.mempoolSize = (typeof p.mempool_size === "number") ? p.mempool_size : state.mempoolSize;
      // Re-render only pages that show this data. Adding pages here as
      // they grow chain-aware (mining, swap status, etc.).
      if (state.page === "dashboard" || state.page === "history") {
        renderShell();
      }
    });
  } catch (e) {
    console.warn("[subscribeToChainState] event.listen failed:", e);
  }
}

// Subscribe to mining-side state changes: is_mining, hashrate, blocks_found,
// threads. Emitted by Rust on start/stop (state-change) AND every 3s while
// mining (periodic tick — keeps the UI alive during long runs).
async function subscribeToMiningStats() {
  if (!IS_TAURI || !window.__TAURI__.event) return;
  try {
    await window.__TAURI__.event.listen("mining_stats", (event) => {
      const p = event.payload || {};
      const wasOn = mining.on;
      mining.on        = !!p.is_mining;
      mining.hashrate  = (typeof p.hashrate === "number") ? p.hashrate : mining.hashrate;
      mining.blocks    = (typeof p.blocks_found === "number") ? p.blocks_found : mining.blocks;
      mining.threads   = (typeof p.threads === "number") ? p.threads : mining.threads;
      mining.algorithm = p.algorithm || mining.algorithm || "RandomX";
      // Session bookkeeping: on the off→on transition start the uptime
      // clock and clear the prior session's trend; on on→off stop feeding
      // the sparkline so it freezes at the last live shape.
      if (mining.on && !wasOn) {
        mining.startedAt = Date.now();
        mining.samples = [];
        mining.peak = 0;
      }
      if (mining.on) {
        recordHashrateSample(mining.hashrate);
      }
      if (state.page === "mining" || state.page === "dashboard") {
        renderShell();
      }
    });

    // block_found: distinct from mining_stats — fires only on the rare
    // event that the rig actually finds a block. We show a toast,
    // bump the session counter, and trigger a wallet scan so the
    // coinbase reward shows up in the balance / activity list.
    await window.__TAURI__.event.listen("block_found", async (event) => {
      const p = event.payload || {};
      const delta = p.delta ?? 1;
      mining.blocksThisSession += delta;
      const word = delta === 1 ? "block" : "blocks";
      showMiningToast(`Mined ${delta} ${word}! Total this session: ${mining.blocksThisSession}.`);
      // Re-scan so the coinbase reward lands in the wallet's UTXO view.
      // Best-effort; failures are non-fatal.
      try {
        await invoke("scan_wallet");
      } catch (e) {
        console.warn("[block_found] auto-rescan failed:", e);
      }
      if (state.page === "mining" || state.page === "dashboard") {
        renderShell();
      }
    });
  } catch (e) {
    console.warn("[subscribeToMiningStats] event.listen failed:", e);
  }
}

// Subscribe to wallet-side state changes: balance, scanned-height, tx count.
// Emitted by Rust on unlock/lock/scan/send/restore. Distinct from
// chain_state (which is node-side) so each can fire independently and
// the UI doesn't conflate "node ticked a block" with "you received funds."
async function subscribeToWalletState() {
  if (!IS_TAURI || !window.__TAURI__.event) return;
  try {
    await window.__TAURI__.event.listen("wallet_state", async (event) => {
      const p = event.payload || {};
      // Atomic units → display CYNC (12 decimal places).
      const ATOMIC_PER_CYNC = 1e12;
      if (typeof p.balance_total === "number") {
        state.balance = p.balance_total / ATOMIC_PER_CYNC;
      }
      if (typeof p.balance_unlocked === "number") {
        state.balanceUnlocked = p.balance_unlocked / ATOMIC_PER_CYNC;
      }
      if (typeof p.scanned_height === "number") {
        state.scannedHeight = p.scanned_height;
      }
      if (typeof p.utxo_count === "number") {
        state.utxoCount = p.utxo_count;
      }
      if (typeof p.transactions_count === "number") {
        state.txCount = p.transactions_count;
      }
      // Task #7+#8: reorg-notification fields. Stored on state so the
      // banner stays visible across re-renders until the user clicks
      // dismiss (which calls dismiss_reorg_notification → re-emits a
      // wallet_state with both fields absent → these clear).
      if (typeof p.lastReorgAtHeight === "number") {
        state.lastReorgAtHeight = p.lastReorgAtHeight;
      } else {
        state.lastReorgAtHeight = null;
      }
      if (typeof p.lastReorgDepth === "number") {
        state.lastReorgDepth = p.lastReorgDepth;
      } else {
        state.lastReorgDepth = null;
      }
      // When the tx count changes, refresh the actual list so dashboard /
      // history show the new transactions. Fire-and-forget; the next
      // re-render will pick up state.transactions.
      try {
        const txs = await invoke("get_transactions");
        if (txs && Array.isArray(txs.txs)) state.transactions = txs.txs;
        else if (Array.isArray(txs)) state.transactions = txs;
      } catch (e) { /* leave state.transactions as-is on failure */ }
      // Dashboard + history both show balance; re-render when relevant.
      // Always re-render on reorg-state change so the banner can appear
      // or disappear regardless of which page is active.
      if (state.page === "dashboard" || state.page === "history"
          || state.lastReorgAtHeight !== null) {
        renderShell();
      }
    });

    // tx_received: a stronger signal — "something just arrived." UI can
    // attach toasts, animate the activity list, etc. For now, log + re-
    // render history if open. Toast wiring is a future enhancement.
    await window.__TAURI__.event.listen("tx_received", (event) => {
      const p = event.payload || {};
      console.info("[tx_received]", p);
      if (state.page === "history" || state.page === "dashboard") {
        renderShell();
      }
    });
  } catch (e) {
    console.warn("[subscribeToWalletState] event.listen failed:", e);
  }
}

// ─── Splash screen ────────────────────────────────────────────────
const SPLASH_DURATION_MS = 1400;
const SPLASH_FADE_MS = 400;

function renderSplash() {
  app.innerHTML = `
    <div class="splash" id="splash">
      <div class="splash__hero">
        <div class="splash__logo-wrap">
          <div class="splash__logo-glow"></div>
          <div class="splash__logo">${LOGO_SVG}</div>
        </div>
        <div class="splash__wordmark">
          Coin<span class="splash__wordmark-accent">Cync</span>
        </div>
        <div class="splash__tagline">Privacy that requires no permission</div>
      </div>
      <div class="splash__progress">
        <div class="splash__progress-fill" id="splashProgress"></div>
      </div>
      <div class="splash__version">v2.0.0 · alpha</div>
    </div>
  `;

  const fill = document.getElementById("splashProgress");
  const start = performance.now();
  function tick(now) {
    const elapsed = now - start;
    const pct = Math.min(100, (elapsed / (SPLASH_DURATION_MS - SPLASH_FADE_MS)) * 100);
    fill.style.width = pct + "%";
    if (pct < 100) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);

  setTimeout(() => {
    document.getElementById("splash").classList.add("fade-out");
  }, SPLASH_DURATION_MS - SPLASH_FADE_MS);
  // After splash, route based on whether a wallet file exists:
  //   - no wallet on disk → onboarding (Create / Restore choice)
  //   - wallet on disk     → unlock screen
  // Browser-preview mode (no Tauri) always falls through to unlock so
  // the design demo still works.
  setTimeout(async () => {
    let exists = true;
    if (IS_TAURI) {
      try { exists = !!(await invoke("wallet_exists")); }
      catch (e) { console.warn("[wallet_exists] failed:", e); exists = true; }
    }
    if (exists) renderUnlock();
    else renderOnboarding();
  }, SPLASH_DURATION_MS);
}

// ─── Unlock screen ────────────────────────────────────────────────
function renderUnlock() {
  app.innerHTML = `
    <div class="unlock">
      <div class="unlock__card">
        <div class="unlock__logo-wrap">
          <div class="unlock__logo-glow"></div>
          <div class="unlock__logo">${LOGO_SVG}</div>
        </div>
        <div class="unlock__eyebrow">Welcome back</div>
        <h1 class="unlock__title">Unlock your wallet</h1>

        <form class="unlock__form" id="unlockForm">
          <div class="unlock__input-wrap">
            <input id="unlockInput" class="unlock__input" type="password"
                   placeholder="Wallet password" autocomplete="current-password" />
          </div>
          <div class="unlock__status" id="unlockStatus">
            Press <kbd>Enter</kbd> to unlock
          </div>
          <button type="submit" class="unlock__button" id="unlockButton">Unlock</button>
        </form>

        <div class="unlock__footer">
          <div class="unlock__version">CoinCync · v2.0.0</div>
          <button class="unlock__forgot">Forgot password?</button>
        </div>
      </div>
    </div>
  `;

  const input = document.getElementById("unlockInput");
  const button = document.getElementById("unlockButton");
  const status = document.getElementById("unlockStatus");
  const form = document.getElementById("unlockForm");

  // Explicit focus — autofocus attribute is unreliable in Tauri webviews
  // (sometimes the window hasn't received focus when the element mounts,
  // so the attribute is silently ignored). Call .focus() after a tick to
  // guarantee it lands.
  requestAnimationFrame(() => input.focus());

  // Clear error state when the user starts typing. Button stays enabled —
  // validation happens at submit time so the user can always click it.
  input.addEventListener("input", () => {
    if (status.classList.contains("is-error")) {
      status.classList.remove("is-error");
      status.innerHTML = `Press <kbd>Enter</kbd> to unlock`;
      input.classList.remove("has-error");
    }
  });

  // Belt-and-suspenders: some webviews don't reliably fire form submit
  // on Enter when an input is focused. The explicit keydown handler
  // routes to the same submit path.
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      e.preventDefault();
      form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit", { cancelable: true }));
    }
  });

  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const pw = input.value;
    if (!pw) {
      input.focus();
      showUnlockError(input, status, button, "Enter your wallet password");
      return;
    }

    button.disabled = true;
    button.innerHTML = `<span class="spinner"></span>Unlocking…`;
    status.classList.remove("is-error");
    status.innerHTML = `Verifying password…`;

    try {
      const ok = await invoke("unlock_wallet", { password: pw });
      if (ok) {
        // Kick off initial wallet-state fetch in the background;
        // Dashboard will render with whatever's cached when it lands.
        primeWalletState();
        renderShell();
        // Trigger an initial chain scan so the balance + transaction
        // list populate without the user needing to hit "Sync" manually.
        // Fire-and-forget — the wallet_state push event will update
        // the UI when the scan completes.
        if (IS_TAURI) {
          invoke("scan_wallet").catch((e) => console.warn("[initial-scan]", e));
        }
      } else {
        showUnlockError(input, status, button, "Incorrect password");
      }
    } catch (err) {
      // Typed errors from Rust arrive as `{ code: "AUTH_INVALID_PASSWORD", ... }`.
      // Legacy errors arrive as plain strings — fallback path handles both
      // so we don't regress while other commands are still string-typed.
      showUnlockError(input, status, button, formatWalletError(err));
    }
  });
}

// Translate a WalletError (typed object from Rust) or a legacy string error
// into user-facing text. Pattern-matches on err.code first; falls back to
// the v1 substring-matching for any command that still returns String errors.
function formatWalletError(err) {
  if (err && typeof err === "object" && typeof err.code === "string") {
    switch (err.code) {
      case "AUTH_INVALID_PASSWORD":
        return "Incorrect password";
      case "AUTH_RATE_LIMITED":
        return `Too many attempts — try again in ${err.wait_secs ?? 30}s`;
      case "WALLET_NOT_FOUND":
        return "No wallet found — restore with your seed phrase";
      case "WALLET_INVALID_SEED":
        return `Seed phrase invalid: ${err.reason ?? "unknown reason"}`;
      case "WALLET_SEED_PARSE_FAILED":
        return "Wallet may have been created but the seed phrase couldn't be read. Check the wallet folder.";
      case "WALLET_LOCKED":
        return "Wallet is locked. Please unlock first.";
      case "SESSION_MISSING":
        return "Session expired. Please unlock again.";
      case "INVALID_ADDRESS":
        return `Invalid address: ${err.reason ?? "unrecognised format"}`;
      case "INVALID_AMOUNT":
        return `Invalid amount: ${err.reason ?? "unrecognised number"}`;
      case "LOCK_POISONED":
        return "Internal wallet error. Please restart the app.";
      case "CLI_FAILED":
      case "WALLET_OP_FAILED":
        return err.msg || "Wallet operation failed";
      default:
        return err.code;
    }
  }
  // Legacy string fallback (commands not yet migrated to typed errors)
  let msg = String((err && err.message) || err);
  msg = msg.replace(/^\[[A-Z0-9_]+\]\s*/, "");
  if (/invalid password|incorrect password/i.test(msg)) return "Incorrect password";
  if (/rate.?limit|too.?many/i.test(msg)) return "Too many attempts — try again shortly";
  if (/wallet not found|no wallet/i.test(msg)) return "No wallet found — create one first";
  return msg;
}

function showUnlockError(input, status, button, msg) {
  input.classList.add("has-error");
  status.classList.add("is-error");
  status.innerHTML = msg;
  button.disabled = false;
  button.innerHTML = `Unlock`;
}

// ─── Onboarding (no wallet on disk yet) ────────────────────────────
// Two paths: create a fresh wallet (generates a new seed) OR restore from
// an existing seed phrase. Renders after the splash if `wallet_exists`
// returned false.
function renderOnboarding() {
  app.innerHTML = `
    <div class="unlock">
      <div class="unlock__card" style="max-width: 560px;">
        <div class="unlock__logo-wrap">
          <div class="unlock__logo-glow"></div>
          <div class="unlock__logo">${LOGO_SVG}</div>
        </div>
        <div class="unlock__eyebrow">Welcome to CoinCync</div>
        <h1 class="unlock__title">Set up your wallet</h1>

        <div class="onboarding-choices">
          <button class="onboarding-choice" id="ob-create">
            <div class="onboarding-choice__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            </div>
            <div class="onboarding-choice__title">Create new wallet</div>
            <div class="onboarding-choice__body">
              First time? We'll generate a fresh 24-word seed phrase.
              You'll back it up before we go any further.
            </div>
          </button>
          <button class="onboarding-choice" id="ob-restore">
            <div class="onboarding-choice__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 1 0 3-6.7"/><polyline points="3 4 3 12 11 12"/></svg>
            </div>
            <div class="onboarding-choice__title">Restore from seed phrase</div>
            <div class="onboarding-choice__body">
              Already have a CoinCync wallet? Paste your 24-word seed and
              set a new password on this device.
            </div>
          </button>
        </div>

        <div class="unlock__footer">
          <div class="unlock__version">CoinCync · v2.0.0</div>
        </div>
      </div>
    </div>
  `;
  document.getElementById("ob-create").addEventListener("click", renderCreateWallet);
  document.getElementById("ob-restore").addEventListener("click", renderRestoreWallet);
}

// ─── Create-wallet flow ────────────────────────────────────────────
// Two-step: (1) pick a password, (2) write down the generated seed.
function renderCreateWallet() {
  app.innerHTML = `
    <div class="unlock">
      <div class="unlock__card" style="max-width: 520px;">
        <div class="unlock__logo-wrap">
          <div class="unlock__logo-glow"></div>
          <div class="unlock__logo">${LOGO_SVG}</div>
        </div>
        <div class="unlock__eyebrow">Step 1 of 2</div>
        <h1 class="unlock__title">Set a password</h1>
        <div class="unlock__status">
          This password encrypts your wallet on this device. It is NOT recoverable —
          if you forget it, restore from your seed phrase (which you'll see next).
        </div>

        <form class="unlock__form" id="createForm">
          <div class="unlock__input-wrap">
            <input id="pw1" class="unlock__input" type="password"
                   placeholder="Choose a password" autocomplete="new-password" autofocus />
          </div>
          <div class="unlock__input-wrap">
            <input id="pw2" class="unlock__input" type="password"
                   placeholder="Confirm password" autocomplete="new-password" />
          </div>
          <div class="unlock__status" id="createStatus"></div>
          <button type="submit" class="unlock__button" id="createBtn" disabled>Generate wallet</button>
        </form>

        <div class="unlock__footer">
          <button class="unlock__forgot" id="createBack">← Back</button>
        </div>
      </div>
    </div>
  `;
  const pw1 = document.getElementById("pw1");
  const pw2 = document.getElementById("pw2");
  const btn = document.getElementById("createBtn");
  const status = document.getElementById("createStatus");
  const updateEnabled = () => {
    const ok = pw1.value.length >= 8 && pw1.value === pw2.value;
    btn.disabled = !ok;
    if (pw2.value && pw1.value !== pw2.value) {
      status.classList.add("is-error");
      status.textContent = "Passwords don't match";
    } else if (pw1.value && pw1.value.length < 8) {
      status.classList.add("is-error");
      status.textContent = "At least 8 characters";
    } else {
      status.classList.remove("is-error");
      status.textContent = "";
    }
  };
  pw1.addEventListener("input", updateEnabled);
  pw2.addEventListener("input", updateEnabled);
  document.getElementById("createBack").addEventListener("click", renderOnboarding);
  document.getElementById("createForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span>Generating…`;
    try {
      const seed = await invoke("create_wallet", { password: pw1.value });
      renderSeedBackup(seed, pw1.value);
    } catch (err) {
      status.classList.add("is-error");
      status.textContent = formatWalletError(err);
      btn.disabled = false;
      btn.innerHTML = "Generate wallet";
    }
  });
}

// ─── Seed backup screen ───────────────────────────────────────────
// Mandatory acknowledgement before routing to dashboard. The seed is
// shown ONCE — losing it = losing the wallet. Strong warning copy.
function renderSeedBackup(seed) {
  const words = seed.trim().split(/\s+/);
  app.innerHTML = `
    <div class="unlock">
      <div class="unlock__card" style="max-width: 720px;">
        <div class="unlock__eyebrow" style="color: var(--amber);">Step 2 of 2 · Write this down</div>
        <h1 class="unlock__title">Your recovery seed</h1>
        <div class="unlock__status" style="color: var(--text-secondary); margin-bottom: var(--sp-6);">
          This 24-word phrase is the ONLY way to recover your wallet if you lose
          this device or forget your password. <strong>Write it down on paper</strong>
          and store it somewhere safe. Never type it into a website, never share it,
          never store it as a screenshot or in cloud storage.
        </div>
        <div class="seed-grid">
          ${words.map((w, i) => `
            <div class="seed-word">
              <span class="seed-word__num">${i + 1}</span>
              <span class="seed-word__text">${w}</span>
            </div>
          `).join("")}
        </div>
        <label class="seed-ack">
          <input type="checkbox" id="seedAck" />
          <span>I've written down my seed phrase and stored it safely.</span>
        </label>
        <button class="unlock__button" id="seedContinue" disabled>Continue to wallet</button>
      </div>
    </div>
  `;
  const ack = document.getElementById("seedAck");
  const btn = document.getElementById("seedContinue");
  ack.addEventListener("change", () => { btn.disabled = !ack.checked; });
  btn.addEventListener("click", async () => {
    // The wallet is already unlocked (create_wallet sets unlocked=true server-side
    // + emits wallet_state). Route to dashboard, prime, kick off a scan.
    renderShell();
    primeWalletState();
    if (IS_TAURI) {
      invoke("scan_wallet").catch((e) => console.warn("[initial-scan]", e));
    }
  });
}

// ─── Restore-from-seed flow ───────────────────────────────────────
function renderRestoreWallet() {
  app.innerHTML = `
    <div class="unlock">
      <div class="unlock__card" style="max-width: 600px;">
        <div class="unlock__logo-wrap">
          <div class="unlock__logo-glow"></div>
          <div class="unlock__logo">${LOGO_SVG}</div>
        </div>
        <div class="unlock__eyebrow">Restore from seed</div>
        <h1 class="unlock__title">Enter your 24-word seed</h1>

        <form class="unlock__form" id="restoreForm">
          <textarea id="seedInput" class="unlock__input" style="min-height: 110px; resize: vertical;"
                    placeholder="word1 word2 word3 ..."
                    autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false"></textarea>
          <div class="unlock__input-wrap">
            <input id="rpw1" class="unlock__input" type="password"
                   placeholder="New password for this device" autocomplete="new-password" />
          </div>
          <div class="unlock__input-wrap">
            <input id="rpw2" class="unlock__input" type="password"
                   placeholder="Confirm password" autocomplete="new-password" />
          </div>
          <div class="unlock__status" id="restoreStatus"></div>
          <button type="submit" class="unlock__button" id="restoreBtn" disabled>Restore wallet</button>
        </form>

        <div class="unlock__footer">
          <button class="unlock__forgot" id="restoreBack">← Back</button>
        </div>
      </div>
    </div>
  `;
  const seedI = document.getElementById("seedInput");
  const pw1 = document.getElementById("rpw1");
  const pw2 = document.getElementById("rpw2");
  const btn = document.getElementById("restoreBtn");
  const status = document.getElementById("restoreStatus");
  const updateEnabled = () => {
    const wordCount = seedI.value.trim().split(/\s+/).filter(Boolean).length;
    const seedOk = wordCount === 12 || wordCount === 24;
    const pwOk = pw1.value.length >= 8 && pw1.value === pw2.value;
    btn.disabled = !(seedOk && pwOk);
    if (seedI.value && !seedOk) {
      status.classList.add("is-error");
      status.textContent = `Seed phrase should be 12 or 24 words (found ${wordCount})`;
    } else if (pw2.value && pw1.value !== pw2.value) {
      status.classList.add("is-error");
      status.textContent = "Passwords don't match";
    } else {
      status.classList.remove("is-error");
      status.textContent = "";
    }
  };
  [seedI, pw1, pw2].forEach((el) => el.addEventListener("input", updateEnabled));
  document.getElementById("restoreBack").addEventListener("click", renderOnboarding);
  document.getElementById("restoreForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner"></span>Restoring…`;
    try {
      await invoke("restore_wallet", { seed: seedI.value.trim(), password: pw1.value });
      renderShell();
      primeWalletState();
      if (IS_TAURI) {
        invoke("scan_wallet").catch((e) => console.warn("[initial-scan]", e));
      }
    } catch (err) {
      status.classList.add("is-error");
      status.textContent = formatWalletError(err);
      btn.disabled = false;
      btn.innerHTML = "Restore wallet";
    }
  });
}

// Fetch + cache the wallet state so the Dashboard renders quickly.
async function primeWalletState() {
  try {
    const [bal, blk, addr, walletPath, netInfo] = await Promise.allSettled([
      invoke("get_balance"),
      invoke("get_block_height"),
      invoke("get_wallet_address"),
      invoke("wallet_path"),
      invoke("get_network_info"),
    ]);
    if (walletPath.status === "fulfilled" && typeof walletPath.value === "string") {
      state.walletFilePath = walletPath.value;
    }
    if (netInfo.status === "fulfilled" && netInfo.value) {
      // { version, network, connections }. Derive the display ticker from
      // the network: only mainnet uses the bare "CYNC" symbol.
      state.network = netInfo.value.network || state.network;
      state.nodeVersion = netInfo.value.version || state.nodeVersion;
      state.unit = state.network === "mainnet" ? "CYNC" : "tCYNC";
    }
    if (bal.status === "fulfilled" && bal.value) {
      // v1 returns total/unlocked/locked as strings; v2 dashboard
      // expects a numeric `state.balance` for now.
      const total = parseFloat(bal.value.total || bal.value.unlocked || 0);
      state.balance = total;
    }
    if (blk.status === "fulfilled" && blk.value) {
      state.blockHeight = blk.value.height || blk.value.chainHeight || 0;
      state.syncPct = blk.value.syncPct ?? 100;
    }
    if (addr.status === "fulfilled" && addr.value) {
      state.address = addr.value;
    }
    // Re-render only if we're on a page that shows this data.
    if (state.page === "dashboard" || state.page === "receive") {
      renderShell();
    }
  } catch (e) {
    console.warn("[primeWalletState]", e);
  }
}

// Refresh the node's live fee estimate and, if the user is on the Send
// view, re-render so the tiers + review pane reflect current pricing.
// Best-effort: on any error we keep whatever estimate (or static fallback)
// is already in place.
async function refreshFeeEstimate() {
  try {
    const fe = await invoke("get_fee_estimate");
    if (fe && (fe.normal || fe.slow || fe.fast || fe.flash)) {
      state.feeEstimate = fe;
      if (state.page === "send") renderShell();
    }
  } catch (e) {
    console.warn("[refreshFeeEstimate]", e);
  }
}

// ─── App shell (sidebar + main column) ────────────────────────────
const NAV = [
  { group: "Wallet", items: [
    { id: "dashboard", label: "Dashboard", icon: "dashboard" },
    { id: "send",      label: "Send",      icon: "send" },
    { id: "receive",   label: "Receive",   icon: "receive" },
    { id: "history",   label: "History",   icon: "history" },
  ]},
  { group: "Tools", items: [
    { id: "swap",      label: "Swap",      icon: "swap",     badge: "SOON" },
    { id: "addresses", label: "Addresses", icon: "addresses" },
    { id: "mining",    label: "Mining",    icon: "mining" },
    { id: "multisig",  label: "Multi-sig", icon: "multisig", badge: "SOON" },
  ]},
  { group: "System", items: [
    { id: "settings",  label: "Settings",  icon: "settings" },
  ]},
];

function sidebarHtml() {
  return `
    <aside class="sidebar">
      <div class="sidebar__brand">
        <div class="sidebar__brand-logo">${LOGO_SVG}</div>
        <div class="sidebar__brand-name">Coin<span>Cync</span></div>
      </div>
      ${NAV.map(group => `
        <div class="sidebar__group">
          <div class="sidebar__group-label">${group.group}</div>
          ${group.items.map(item => `
            <button class="sidebar__item ${item.id === state.page ? "is-active" : ""}"
                    data-page="${item.id}" style="position: relative;">
              <span class="sidebar__item-icon">${ICONS[item.icon] || ""}</span>
              <span>${item.label}</span>
              ${item.badge ? `<span class="sidebar__item-badge">${item.badge}</span>` : ""}
            </button>
          `).join("")}
        </div>
      `).join("")}
      <div class="sidebar__footer">
        <div class="sidebar__status">
          <div class="sidebar__status-dot"></div>
          <span>Connected · testnet</span>
        </div>
      </div>
    </aside>
  `;
}

function pageHtml() {
  switch (state.page) {
    case "dashboard": return dashboardHtml();
    case "send":      return sendHtml();
    case "receive":   return receiveHtml();
    case "swap":      return swapHtml();
    case "history":   return historyHtml();
    case "settings":  return settingsHtml();
    case "addresses": return addressesHtml();
    case "mining":    return miningHtml();
    case "multisig":  return multisigHtml();
    default:          return dashboardHtml();
  }
}

function renderShell() {
  app.innerHTML = `
    <div class="shell">
      ${sidebarHtml()}
      <main class="main" id="mainContent">${reorgBannerHtml()}${pageHtml()}</main>
    </div>
  `;

  // Async post-mount: fill in any .qr-placeholder elements via the
  // Rust `generate_qr_svg` Tauri command. Fire-and-forget — errors
  // surface inline in the placeholder.
  mountQrCodes();

  // Wire nav clicks
  app.querySelectorAll("[data-page]").forEach(btn => {
    btn.addEventListener("click", () => {
      state.page = btn.dataset.page;
      renderShell();
    });
  });

  // Wire dashboard action buttons (if present)
  app.querySelectorAll("[data-action]").forEach(btn => {
    btn.addEventListener("click", () => {
      state.page = btn.dataset.action;
      renderShell();
    });
  });

  // Wire reorg-banner dismiss (Task #8). When present, calls back to
  // Rust to clear AppState.last_reorg_* + re-emit wallet_state.
  const dismissBtn = app.querySelector("[data-reorg-dismiss]");
  if (dismissBtn) {
    dismissBtn.addEventListener("click", async () => {
      try {
        await invoke("dismiss_reorg_notification");
      } catch (e) {
        console.warn("[reorgBanner] dismiss failed:", e);
        // Local fallback so the user can still close it even if the
        // backend call fails — re-emit will eventually re-clear.
        state.lastReorgAtHeight = null;
        state.lastReorgDepth = null;
        renderShell();
      }
    });
  }

  // Wire page-specific handlers
  if (state.page === "send")     wireSend();
  if (state.page === "receive")  wireReceive();
  if (state.page === "swap")     wireSwap();
  if (state.page === "history")  wireHistory();
  if (state.page === "settings") wireSettings();
  if (state.page === "mining")   wireMining();
  if (state.page === "multisig") wireMultisig();
}

// Task #8: reorg-notification banner. Renders at the top of <main> on
// every page while state.lastReorgAtHeight is non-null. Dismissible
// via the X button (which invokes dismiss_reorg_notification on the
// Rust side). The wording follows the design doc: "Chain reorg
// detected at depth N — balance updated".
function reorgBannerHtml() {
  if (state.lastReorgAtHeight === null || state.lastReorgAtHeight === undefined) {
    return "";
  }
  const depth = state.lastReorgDepth ?? 0;
  const height = state.lastReorgAtHeight;
  const depthWord = depth === 1 ? "block" : "blocks";
  return `
    <div class="reorg-banner" role="status" aria-live="polite">
      <div class="reorg-banner__icon" aria-hidden="true">⟳</div>
      <div class="reorg-banner__body">
        <div class="reorg-banner__title">Chain reorganization detected</div>
        <div class="reorg-banner__detail">
          Rewound ${depth} ${depthWord} to block ${height.toLocaleString()}. Your balance has been updated.
        </div>
      </div>
      <button class="reorg-banner__dismiss" data-reorg-dismiss
              aria-label="Dismiss reorg notification">
        ×
      </button>
    </div>
  `;
}

// ─── Dashboard ────────────────────────────────────────────────────
function dashboardHtml() {
  // Real activities sourced from state.transactions (populated by
  // get_transactions invoke + wallet_state event). Map to the display
  // shape used by the activity-row template. Show up to 5 newest.
  const activities = state.transactions.slice(0, 5).map(tx => {
    const inbound = tx.tx_type !== "sent" && tx.tx_type !== "out";
    const sign = inbound ? "+" : "−";
    return {
      kind: inbound ? "in" : "out",
      label: inbound
        ? (tx.tx_kind === "coinbase" ? "Mining reward" : "Received")
        : "Sent",
      meta: tx.height ? `Block #${tx.height.toLocaleString()}` : (tx.date || "—"),
      amount: `${sign}${tx.amount || "0.000000"}`,
      // Network-aware ticker: tCYNC on testnet, CYNC on mainnet. Sourced
      // from get_network_info at boot (state.unit), matching the
      // hero-balance + history-page units.
      unit: state.unit,
    };
  });
  const pending = Math.max(0, state.balance - state.balanceUnlocked);

  return `
    <div class="dashboard">
      <header class="main__header">
        <div>
          <h1 class="main__title">Dashboard</h1>
          <div class="main__subtitle">
            <span class="status-dot ${!state.connected ? "is-offline" : (state.isSynced ? "" : "is-syncing")}"></span>
            ${state.connected
              ? `Block ${state.blockHeight.toLocaleString()} · ${state.syncPct >= 100 ? "synced" : `${state.syncPct.toFixed(1)}% synced`} · ${state.peerCount} ${state.peerCount === 1 ? "peer" : "peers"}`
              : `Node offline — reconnecting…`}
          </div>
        </div>
      </header>

      <section class="hero-balance">
        <div class="hero-balance__label">Total balance</div>
        <div class="hero-balance__row">
          <div class="hero-balance__value">${state.balance.toFixed(6)}</div>
          <div class="hero-balance__unit">${state.unit}</div>
        </div>
        <div class="hero-balance__sub">
          <span>${state.balanceUnlocked.toFixed(6)}</span> available · ${pending.toFixed(6)} pending
        </div>
      </section>

      <section class="quick-actions">
        <button class="action-card" data-action="send">
          <div class="action-card__icon-wrap">${ICONS.arrowUp}</div>
          <div>
            <div class="action-card__label">Send</div>
            <div class="action-card__sub">Pay anyone, anywhere</div>
          </div>
        </button>
        <button class="action-card" data-action="receive">
          <div class="action-card__icon-wrap is-secondary">${ICONS.arrowDown}</div>
          <div>
            <div class="action-card__label">Receive</div>
            <div class="action-card__sub">Show this to get paid</div>
          </div>
        </button>
        <button class="action-card" data-action="swap">
          <div class="action-card__icon-wrap is-secondary">${ICONS.swap}</div>
          <div>
            <div class="action-card__label">
              Swap
              <span class="action-card__chip">v1.1</span>
            </div>
            <div class="action-card__sub">Trade CYNC ↔ BTC · preview</div>
          </div>
        </button>
        <button class="action-card" data-action="mining">
          <div class="action-card__icon-wrap is-secondary">${ICONS.mining}</div>
          <div>
            <div class="action-card__label">Mine</div>
            <div class="action-card__sub">Earn while you sleep</div>
          </div>
        </button>
      </section>

      <section class="section">
        <div class="section__head">
          <h2 class="section__title">Recent activity</h2>
          ${activities.length > 0
            ? `<button class="section__link" data-action="history">View all →</button>`
            : ``}
        </div>
        <div class="activity-list">
          ${activities.length === 0 ? `
            <div class="activity-empty">
              <div class="activity-empty__art">${ICONS.arrowDown}</div>
              <div class="activity-empty__title">Receive your first CYNC</div>
              <div class="activity-empty__body">
                Your transactions will show up here. To get started, share your
                stealth address — only you can see what arrives.
              </div>
              <button class="activity-empty__cta" data-action="receive">
                Show my address
              </button>
            </div>
          ` : activities.map(a => `
            <div class="activity-row">
              <div class="activity-icon is-${a.kind}">
                ${a.kind === "in" ? ICONS.arrowDown : ICONS.arrowUp}
              </div>
              <div class="activity-body">
                <div class="activity-body__label">${a.label}</div>
                <div class="activity-body__meta">${a.meta}</div>
              </div>
              <div class="activity-amount is-${a.kind}">
                ${a.amount}
                <span class="activity-amount__unit">${a.unit}</span>
              </div>
            </div>
          `).join("")}
        </div>
      </section>
    </div>
  `;
}

// ─── Send screen ──────────────────────────────────────────────────
function sendHtml() {
  // Costs come from the node's live get_fee_estimate when available
  // (state.feeEstimate, populated by refreshFeeEstimate on Send open);
  // otherwise fall back to static placeholders. Node values are 12-dp
  // strings — trim to 6 dp for display.
  const fee6 = (v, fallback) => {
    const n = parseFloat(v);
    return Number.isFinite(n) ? n.toFixed(6) : fallback;
  };
  const fe = state.feeEstimate;
  const feeTiers = [
    { id: "slow",   name: "Slow",   time: "~30 min",  cost: fee6(fe?.slow,   "0.000084") },
    { id: "normal", name: "Normal", time: "~5 min",   cost: fee6(fe?.normal, "0.000142") },
    { id: "fast",   name: "Fast",   time: "<1 min",   cost: fee6(fe?.fast,   "0.000284") },
    { id: "flash",  name: "Flash",  time: "Next blk", cost: fee6(fe?.flash,  "0.000568") },
  ];

  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Send</h1>
        <div class="main__subtitle">Outgoing transaction</div>
      </div>
    </header>
    <div class="send">
      <div>
        <div class="send-amount">
          <div class="send-amount__label">Amount to send</div>
          <div class="send-amount__row">
            <input class="send-amount__input" id="sendAmount" type="text"
                   placeholder="0.000000" inputmode="decimal" />
            <div class="send-amount__unit">${state.unit}</div>
          </div>
          <div class="send-amount__available">
            Available <strong style="color: var(--text-secondary);">${state.balance.toFixed(6)}</strong> ${state.unit}
            <button class="send-amount__max" id="sendMax">MAX</button>
          </div>

          <div class="send-fields">
            <div class="field-group">
              <div class="field-label">
                <span>Recipient address</span>
                <span class="field-label__hint" id="addrHint">${state.unit}… or .cync handle</span>
              </div>
              <div class="field-input">
                <input type="text" placeholder="${state.unit}…" id="sendAddress" />
                <div class="field-input__actions">
                  <button class="field-icon-btn" title="Paste">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/></svg>
                  </button>
                  <button class="field-icon-btn" title="Scan QR">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M23 7V3h-4M1 17v4h4M1 7V3h4M23 17v4h-4"/><rect x="7" y="7" width="3" height="3"/><rect x="14" y="7" width="3" height="3"/><rect x="7" y="14" width="3" height="3"/><rect x="14" y="14" width="3" height="3"/></svg>
                  </button>
                </div>
              </div>
            </div>

            <div class="field-group">
              <div class="field-label">
                <span>Memo</span>
                <span class="field-label__hint">Encrypted on-chain · max 256 chars</span>
              </div>
              <div class="field-input">
                <textarea placeholder="Optional note (visible only to recipient)" id="sendMemo"></textarea>
              </div>
            </div>

            <div class="field-group">
              <div class="field-label">
                <span>Fee tier</span>
                <span class="field-label__hint">Higher = faster confirmation</span>
              </div>
              <div class="fee-tiers" id="feeTiers">
                ${feeTiers.map((f, i) => `
                  <button class="fee-tier ${i === 1 ? "is-active" : ""}" data-fee="${f.id}">
                    <div class="fee-tier__name">${f.name}</div>
                    <div class="fee-tier__time">${f.time}</div>
                    <div class="fee-tier__cost">${f.cost} ${state.unit}</div>
                  </button>
                `).join("")}
              </div>
            </div>
          </div>
        </div>
      </div>

      <aside class="send-summary">
        <div class="send-summary__title">Review</div>
        <div class="send-summary__row">
          <span>To</span>
          <span id="summaryTo" style="color: var(--text-tertiary);">—</span>
        </div>
        <div class="send-summary__row">
          <span>Amount</span>
          <span id="summaryAmount">0.000000 ${state.unit}</span>
        </div>
        <div class="send-summary__row">
          <span>Network fee</span>
          <span id="summaryFee">${feeTiers[1].cost} ${state.unit}</span>
        </div>
        <div class="send-summary__row">
          <span>Privacy</span>
          <span style="color: var(--green);">Stealth · CLSAG ring</span>
        </div>
        <div class="send-summary__total">
          <span class="send-summary__total-label">Total</span>
          <span class="send-summary__total-value" id="summaryTotal">${feeTiers[1].cost}<span>${state.unit}</span></span>
        </div>
        <button class="primary-button" disabled>Send transaction</button>
      </aside>
    </div>
  `;
}

function wireSend() {
  app.querySelectorAll(".fee-tier").forEach(t => {
    t.addEventListener("click", () => {
      app.querySelectorAll(".fee-tier").forEach(x => x.classList.remove("is-active"));
      t.classList.add("is-active");
      updateSendButton();
    });
  });
  const maxBtn = document.getElementById("sendMax");
  const amount = document.getElementById("sendAmount");
  const address = document.getElementById("sendAddress");
  const memo = document.getElementById("sendMemo");
  if (maxBtn && amount) {
    maxBtn.addEventListener("click", () => {
      amount.value = state.balance.toFixed(6);
      updateSendButton();
    });
  }
  [amount, address, memo].forEach(el => el && el.addEventListener("input", updateSendButton));

  // Live recipient-address validation. Runs on blur (not per-keystroke —
  // validate_address shells out to the wallet CLI, so debounce to field
  // exit). Updates the recipient hint with the verified address type or the
  // rejection reason, and records validity so the Send handler can block.
  const addrHint = document.getElementById("addrHint");
  const addrHintDefault = addrHint ? addrHint.textContent : "";
  let addrValidated = null; // null=unknown, true/false once checked
  if (address && addrHint) {
    address.addEventListener("blur", async () => {
      const value = address.value.trim();
      if (!value) {
        addrValidated = null;
        addrHint.textContent = addrHintDefault;
        addrHint.style.color = "";
        address.classList.remove("is-valid", "is-invalid");
        return;
      }
      addrHint.textContent = "Checking address…";
      addrHint.style.color = "var(--text-tertiary)";
      try {
        const res = await invoke("validate_address", { address: value });
        if (res && res.valid) {
          addrValidated = true;
          addrHint.textContent = `✓ Valid ${res.type || "stealth"} address`;
          addrHint.style.color = "var(--green)";
          address.classList.add("is-valid");
          address.classList.remove("is-invalid");
        } else {
          addrValidated = false;
          addrHint.textContent = `✗ ${(res && res.reason) || "invalid address"}`;
          addrHint.style.color = "var(--red, #e5484d)";
          address.classList.add("is-invalid");
          address.classList.remove("is-valid");
        }
      } catch (e) {
        // Validation is best-effort — a CLI error shouldn't hard-block the
        // user (the node re-validates on submit). Fall back to neutral.
        addrValidated = null;
        addrHint.textContent = addrHintDefault;
        addrHint.style.color = "";
        address.classList.remove("is-valid", "is-invalid");
      }
    });
    // Clear the verdict as soon as the user edits again.
    address.addEventListener("input", () => {
      addrValidated = null;
      addrHint.textContent = addrHintDefault;
      addrHint.style.color = "";
      address.classList.remove("is-valid", "is-invalid");
    });
  }

  // Pull a live fee estimate from the node the first time the Send view
  // mounts, then re-render so the tiers/summary reflect real mempool
  // pricing. Guarded on null so the re-render doesn't re-trigger a fetch
  // (renderShell re-runs wireSend), which would loop.
  if (!state.feeEstimate) refreshFeeEstimate();

  const sendBtn = app.querySelector(".primary-button");
  if (sendBtn) {
    sendBtn.addEventListener("click", async () => {
      const amt  = amount?.value.trim() || "";
      const to   = address?.value.trim() || "";
      const note = memo?.value.trim() || "";
      const fee  = app.querySelector(".fee-tier.is-active")?.dataset.fee || "normal";

      if (!to || parseFloat(amt) <= 0) return;
      if (addrValidated === false) {
        showToast("Recipient address failed validation — check it and try again", "error");
        return;
      }

      sendBtn.disabled = true;
      sendBtn.textContent = "Sending…";
      try {
        const result = await invoke("send_transaction", {
          params: { to, amount: amt, memo: note || null, priority: fee },
        });
        const txid = result?.txid || "(no txid)";
        // Truncate txid for toast (full id still in clipboard).
        const shortTxid = txid.length > 16 ? `${txid.slice(0, 8)}…${txid.slice(-6)}` : txid;
        showToast(`Sent ✓  ·  ${shortTxid}`, "success");
        amount.value = ""; address.value = ""; memo.value = "";
        updateSendButton();
      } catch (e) {
        showToast(`Send failed: ${e.message || e}`, "error");
      }
      sendBtn.disabled = false;
      sendBtn.textContent = "Send transaction";
    });
  }

  function updateSendButton() {
    const valid = parseFloat(amount?.value || 0) > 0 && (address?.value || "").trim().length > 0;
    if (sendBtn) sendBtn.disabled = !valid;
    updateSummary();
  }

  // Reactive review pane (Task: v2 polish). Updates the right-side
  // summary's To / Amount / Fee / Total fields whenever the form
  // mutates. Without this the panel showed hardcoded zeros + dash
  // regardless of user input — a confusing UX gap.
  function updateSummary() {
    const summaryTo     = document.getElementById("summaryTo");
    const summaryAmount = document.getElementById("summaryAmount");
    const summaryFee    = document.getElementById("summaryFee");
    const summaryTotal  = document.getElementById("summaryTotal");

    const amt    = parseFloat(amount?.value || 0);
    const to     = (address?.value || "").trim();
    const feeTier = app.querySelector(".fee-tier.is-active");
    const feeTxt = feeTier?.querySelector(".fee-tier__cost")?.textContent || `0.000142 ${state.unit}`;
    const feeNum = parseFloat(feeTxt) || 0;
    const total  = amt + feeNum;

    if (summaryTo) {
      if (to.length === 0) {
        summaryTo.textContent = "—";
        summaryTo.style.color = "var(--text-tertiary)";
      } else {
        // Truncate long addresses to fit the panel
        summaryTo.textContent = to.length > 16
          ? `${to.slice(0, 8)}…${to.slice(-6)}`
          : to;
        summaryTo.style.color = "var(--text-primary)";
      }
    }
    if (summaryAmount) {
      summaryAmount.textContent = `${(amt || 0).toFixed(6)} ${state.unit}`;
    }
    if (summaryFee) {
      summaryFee.textContent = feeTxt;
    }
    if (summaryTotal) {
      summaryTotal.innerHTML = `${total.toFixed(6)}<span>${state.unit}</span>`;
    }
  }

  // Prime the summary on first render so it reflects whatever may be
  // in the inputs (e.g. after a navigate-away-and-back).
  updateSummary();
}

// ─── Receive screen ───────────────────────────────────────────────
//
// QR rendering pipeline:
//   1. qrSvg() returns a placeholder div with the payload in a data
//      attribute. The placeholder gets injected into the page HTML
//      synchronously (template literals only support sync values).
//   2. After renderShell() injects the HTML, mountQrCodes() runs,
//      finds every .qr-placeholder[data-payload] in the DOM, and
//      invokes the Rust `generate_qr_svg` Tauri command for each.
//      The command uses the workspace's `qrcode` crate to produce
//      real scannable SVG output, which replaces the placeholder.
//
// Browser-preview (no Tauri) uses mockInvoke's `generate_qr_svg`
// case which returns the same decorative-grid pattern the old
// implementation produced — keeps the design preview meaningful
// without bundling a JS QR encoder for the preview-only path.
//
// Wallet addresses are bech32 (`[a-z0-9]` + one `1` separator) so
// they're safe to inline directly into a data attribute — no HTML
// escape needed.
function qrSvg(payload) {
  return `<div class="qr-placeholder" data-payload="${payload}">Generating QR…</div>`;
}

async function mountQrCodes() {
  const placeholders = document.querySelectorAll(".qr-placeholder[data-payload]");
  for (const el of placeholders) {
    const payload = el.getAttribute("data-payload");
    if (!payload) continue;
    try {
      const svg = await invoke("generate_qr_svg", { payload });
      // The qrcode crate's svg renderer returns a complete <svg>...</svg>
      // string. Replace the placeholder wholesale.
      el.outerHTML = svg;
    } catch (e) {
      el.textContent = `QR error: ${e}`;
    }
  }
}

function receiveHtml() {
  const addr = state.address;
  // No address loaded yet — wallet still locked or scan hasn't returned
  // the address. Show a clear empty state instead of the dev-preview
  // placeholder; never display a fake address that could trick a user
  // into copying it and asking someone to send funds there.
  if (!addr) {
    return `
      <header class="main__header">
        <div>
          <h1 class="main__title">Receive</h1>
          <div class="main__subtitle">Stealth address · privacy by default</div>
        </div>
      </header>
      <div class="tools-page">
        <div class="future-banner" style="border-left-color: var(--amber); background: linear-gradient(135deg, rgba(255,201,96,0.12) 0%, transparent 60%), var(--glass-light);">
          <div class="future-banner__icon" style="background: rgba(255,201,96,0.18); border-color: var(--amber); color: var(--amber);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <div class="future-banner__body">
            <div class="future-banner__chip" style="color: var(--amber); border-color: var(--amber); background: rgba(255,201,96,0.12);">Unlock first</div>
            <div class="future-banner__title">Your address loads when the wallet unlocks</div>
            <div class="future-banner__text">
              Receive needs your real stealth address — generated from your wallet's view key. Unlock from the splash so we can load it.
            </div>
          </div>
        </div>
      </div>
    `;
  }
  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Receive</h1>
        <div class="main__subtitle">Stealth address · privacy by default</div>
      </div>
    </header>
    <div class="receive">
      <section class="receive-qr">
        <div class="receive-qr__frame">${qrSvg(addr)}</div>
        <div class="receive-qr__caption">
          <div class="receive-qr__caption-label">Your stealth address</div>
          <div class="receive-qr__caption-value">Copy address to share</div>
        </div>
        <div class="address-pill">
          <div class="address-pill__address">${addr}</div>
          <button class="address-pill__copy" id="receiveCopyBtn">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy
          </button>
        </div>
      </section>

      <aside class="receive-options">
        <div class="option-card">
          <div class="option-card__head">
            <div class="option-card__icon">${ICONS.addresses}</div>
            <div>
              <div class="option-card__title">Generate new address</div>
              <div class="option-card__sub">Fresh stealth address · 32 bytes</div>
            </div>
          </div>
          <div class="option-card__body">
            Every received payment uses a unique one-time output, so no chain observer can link two payments to you. Generating a new "label" address is purely cosmetic — your privacy is the same either way.
          </div>
          <button class="ghost-button">Generate new</button>
        </div>

        <div class="option-card">
          <div class="option-card__head">
            <div class="option-card__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 11.5a8.38 8.38 0 0 1-.9 3.8 8.5 8.5 0 0 1-7.6 4.7 8.38 8.38 0 0 1-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 0 1-.9-3.8 8.5 8.5 0 0 1 4.7-7.6 8.38 8.38 0 0 1 3.8-.9h.5a8.48 8.48 0 0 1 8 8v.5z"/></svg>
            </div>
            <div>
              <div class="option-card__title">Request specific amount</div>
              <div class="option-card__sub">Pre-fill amount + memo for the sender</div>
            </div>
          </div>
          <div class="option-card__body">
            Build a payment URI that opens with an amount and (optional) memo already filled in. Useful for invoicing or one-tap payments at a register.
          </div>
          <button class="ghost-button">Build invoice</button>
        </div>

        <div class="option-card">
          <div class="option-card__head">
            <div class="option-card__icon">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
            </div>
            <div>
              <div class="option-card__title">Show on second screen</div>
              <div class="option-card__sub">Fullscreen QR for register / kiosk use</div>
            </div>
          </div>
          <div class="option-card__body">
            Open a fullscreen view of your QR + amount on a secondary display. Built for retail / event use where you want a clean payment surface in front of the customer.
          </div>
          <button class="ghost-button">Open second screen</button>
        </div>
      </aside>
    </div>
  `;
}

// Wire receive page interactions. Just the Copy button at the moment;
// the "Generate new address" + "Request specific amount" cards in the
// receive-options aside don't have backing commands yet (placeholder
// surfaces — see option-card class on the receive page).
function wireReceive() {
  const copyBtn = document.getElementById("receiveCopyBtn");
  if (!copyBtn) return;
  copyBtn.addEventListener("click", async () => {
    const addr = state.address;
    if (!addr) return;
    const original = copyBtn.innerHTML;
    try {
      await navigator.clipboard.writeText(addr);
      copyBtn.innerHTML = "Copied ✓";
      copyBtn.style.color = "var(--green)";
    } catch (e) {
      console.warn("[wireReceive] clipboard.writeText failed:", e);
      copyBtn.innerHTML = "Press Ctrl+C to copy";
    }
    setTimeout(() => {
      copyBtn.innerHTML = original;
      copyBtn.style.color = "";
    }, 1500);
  });
}

// ─── Swap screen ──────────────────────────────────────────────────
const SWAP_STAGES = [
  { id: "setup",     name: "Setup" },
  { id: "handshake", name: "Handshake" },
  { id: "lock",      name: "Lock" },
  { id: "claim",     name: "Claim" },
  { id: "history",   name: "History" },
];

let swapStage = "setup";

function swapHtml() {
  const stagePanel = (() => {
    if (swapStage === "setup") return setupPanelHtml();
    if (swapStage === "handshake") return placeholderPanelHtml("Handshake", "Paste the invite blob from your counterparty. The wallet decodes the swap_id, amounts, and connect URL automatically.");
    if (swapStage === "lock") return placeholderPanelHtml("Lock", "Broadcast your chain's lock transaction (CYNC for Alice, BTC for Bob). Operator pastes the signed-hex from the chain CLI.");
    if (swapStage === "claim") return placeholderPanelHtml("Claim", "Alice claims BTC first — the claim signature reveals the adaptor secret. Bob then claims CYNC using the revealed secret.");
    if (swapStage === "history") return placeholderPanelHtml("History", "Completed and refunded swaps will appear here.");
    return "";
  })();

  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Atomic Swap</h1>
        <div class="main__subtitle">CYNC ↔ BTC · CIP-001 · no custodial exchange</div>
      </div>
    </header>
    <div class="swap">
      <div class="future-banner">
        <div class="future-banner__icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="future-banner__body">
          <div class="future-banner__chip">Coming in v1.1</div>
          <div class="future-banner__title">Atomic swaps ship after v1.0 mainnet</div>
          <div class="future-banner__text">
            <strong>Trustless CYNC ↔ BTC swaps</strong> via the cyncswap protocol (CIP-001). Implementation is feature-complete with full test coverage; the swap layer ships in <strong>v1.1</strong> after its own dedicated audit clears (~Q1–Q2 2027). The UI below is the design scaffolding — buttons are inert until the v1.1 cutover.
          </div>
        </div>
      </div>
      <div class="swap-stages">
        ${SWAP_STAGES.map((s, i) => `
          <button class="swap-stage ${s.id === swapStage ? "is-active" : ""}" data-stage="${s.id}">
            <div class="swap-stage__num">${i + 1}</div>
            <div class="swap-stage__name">${s.name}</div>
          </button>
        `).join("")}
      </div>
      ${stagePanel}
    </div>
  `;
}

function setupPanelHtml() {
  return `
    <div class="swap-panel">
      <p class="swap-panel__intro">
        Start a new atomic swap. The cryptographic protocol guarantees that either both legs settle or both refund — there is no scenario where your counterparty can take your funds without sending theirs.
      </p>
      <div class="role-chips" id="roleChips">
        <button class="role-chip is-active" data-role="alice">
          <div class="role-chip__name">Alice</div>
          <div class="role-chip__sub">Lock CYNC → receive BTC. You go first on-chain.</div>
        </button>
        <button class="role-chip" data-role="bob">
          <div class="role-chip__name">Bob</div>
          <div class="role-chip__sub">Lock BTC → receive CYNC. You join after Alice initiates.</div>
        </button>
      </div>

      <div class="send-fields">
        <div class="field-group">
          <div class="field-label"><span>CYNC amount you lock</span></div>
          <div class="field-input"><input type="text" placeholder="100.0" inputmode="decimal"/></div>
        </div>
        <div class="field-group">
          <div class="field-label"><span>BTC amount Bob pays</span></div>
          <div class="field-input"><input type="text" placeholder="0.01" inputmode="decimal"/></div>
        </div>
        <div class="field-group">
          <div class="field-label"><span>Your BTC receive address (taproot, P2TR)</span></div>
          <div class="field-input"><input type="text" placeholder="bc1p… or tb1p…"/></div>
        </div>
      </div>

      <button class="primary-button" style="margin-top: var(--sp-6);">Start swap</button>
    </div>
  `;
}

function placeholderPanelHtml(title, body) {
  return `
    <div class="swap-panel">
      <h3 style="font-family: var(--font-display); font-size: var(--fs-xl); font-weight: 400; color: var(--text-primary); margin-bottom: var(--sp-3);">${title}</h3>
      <p class="swap-panel__intro">${body}</p>
      <div class="swap-empty">Form lands in the next slice. The visual scaffold + Tauri wiring path is set; the field details + handlers attach when we wire to the cyncswap CLI.</div>
    </div>
  `;
}

function wireSwap() {
  app.querySelectorAll("[data-stage]").forEach(btn => {
    btn.addEventListener("click", () => {
      swapStage = btn.dataset.stage;
      renderShell();
    });
  });
  app.querySelectorAll("[data-role]").forEach(btn => {
    btn.addEventListener("click", () => {
      app.querySelectorAll("[data-role]").forEach(x => x.classList.remove("is-active"));
      btn.classList.add("is-active");
    });
  });
}

// ─── History screen ───────────────────────────────────────────────
let historyFilter = "all";

function historyHtml() {
  // Build display rows from REAL state.transactions (no mock fixtures).
  // Date-grouping is computed from the height-relative ordering; without
  // a true timestamp on each tx, we lump everything into a single "All"
  // group until the backend exposes per-tx timestamps.
  const rows = state.transactions.map(tx => {
    const inbound = tx.tx_type !== "sent" && tx.tx_type !== "out";
    const kind = tx.tx_kind === "swap" ? "swap" : (inbound ? "in" : "out");
    const sign = inbound ? "+" : "−";
    return {
      kind,
      label: inbound
        ? (tx.tx_kind === "coinbase" ? "Mining reward" : "Received")
        : "Sent",
      meta: tx.memo || (tx.tx_kind === "coinbase" ? "Block reward" : "Stealth output"),
      address: tx.height ? `Block #${tx.height.toLocaleString()}` : "—",
      time: tx.date || "—",
      amount: `${sign}${tx.amount || "0.000000"}`,
      unit: "tCYNC",
    };
  });

  const groups = rows.length > 0
    ? [{ label: "All transactions", rows }]
    : [];

  // Filter
  const filtered = groups.map(g => ({
    ...g,
    rows: g.rows.filter(r => historyFilter === "all" || r.kind === historyFilter),
  })).filter(g => g.rows.length > 0);

  const iconFor = (kind) => kind === "in" ? ICONS.arrowDown : kind === "out" ? ICONS.arrowUp : ICONS.swap;

  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">History</h1>
        <div class="main__subtitle">${filtered.reduce((n, g) => n + g.rows.length, 0)} transactions</div>
      </div>
    </header>
    <div class="history">
      <div class="history-filters">
        <div class="history-search">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>
          <input type="text" placeholder="Search by address, txid, or memo…" />
        </div>
        <div class="filter-chips" id="historyChips">
          ${[
            { id: "all",  label: "All" },
            { id: "in",   label: "Received" },
            { id: "out",  label: "Sent" },
            { id: "swap", label: "Swap" },
          ].map(c => `
            <button class="filter-chip ${historyFilter === c.id ? "is-active" : ""}" data-filter="${c.id}">${c.label}</button>
          `).join("")}
        </div>
      </div>

      ${filtered.length === 0 ? `
        <div class="activity-empty">
          <div class="activity-empty__art">${ICONS.history}</div>
          <div class="activity-empty__title">${state.transactions.length === 0 ? "No transactions yet" : "No matches for this filter"}</div>
          <div class="activity-empty__body">
            ${state.transactions.length === 0
              ? "Your transactions will show up here. Receive or send CYNC to get started — or mine a block to earn a coinbase reward."
              : "Try a different filter chip above."}
          </div>
          ${state.transactions.length === 0
            ? `<button class="activity-empty__cta" data-action="receive">Show my address</button>`
            : ""}
        </div>
      ` : filtered.map(group => `
        <section class="history-group">
          <div class="history-group__label">${group.label}</div>
          <div class="history-list">
            ${group.rows.map(r => `
              <div class="history-row">
                <div class="history-row__icon is-${r.kind}">${iconFor(r.kind)}</div>
                <div>
                  <div class="history-row__body-label">${r.label}</div>
                  <div class="history-row__body-meta">${r.meta} · ${r.time}</div>
                </div>
                <div class="history-row__address">${r.address}</div>
                <div class="history-row__amount is-${r.kind}">
                  ${r.amount}
                  <span class="history-row__amount-unit">${r.unit}</span>
                </div>
              </div>
            `).join("")}
          </div>
        </section>
      `).join("")}
    </div>
  `;
}

function wireHistory() {
  app.querySelectorAll("[data-filter]").forEach(c => {
    c.addEventListener("click", () => {
      historyFilter = c.dataset.filter;
      renderShell();
    });
  });
}

// ─── Settings screen ──────────────────────────────────────────────
let settingsTab = "appearance";

const SETTINGS_TABS = [
  { id: "appearance", label: "Appearance", icon: "settings" },
  { id: "security",   label: "Security",   icon: "multisig" },
  { id: "network",    label: "Network",    icon: "swap" },
  { id: "advanced",   label: "Advanced",   icon: "addresses" },
  { id: "about",      label: "About",      icon: "dashboard" },
];

function settingsHtml() {
  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Settings</h1>
        <div class="main__subtitle">Configure your wallet</div>
      </div>
    </header>
    <div class="settings">
      <nav class="settings-nav">
        ${SETTINGS_TABS.map(t => `
          <button class="settings-nav__item ${settingsTab === t.id ? "is-active" : ""}" data-stab="${t.id}">
            <span class="settings-nav__item-icon">${ICONS[t.icon]}</span>
            <span>${t.label}</span>
          </button>
        `).join("")}
      </nav>
      <div class="settings-main">${settingsTabHtml()}</div>
    </div>
  `;
}

function settingsTabHtml() {
  if (settingsTab === "appearance") {
    return `
      <section class="settings-section">
        <h2 class="settings-section__title">Theme</h2>
        <div class="settings-section__sub">Visual style for the wallet. Persists across launches.</div>
        <div class="settings-card">
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Color scheme</div>
              <div class="settings-row__sub">Dark · Gold · Midnight · Paper (light mode). Click a swatch to preview.</div>
            </div>
            <div class="settings-row__control theme-swatches">
              <div class="theme-swatch theme-swatch--dark ${prefs.theme === 'dark' ? 'is-active' : ''}" data-theme="dark" title="Dark"></div>
              <div class="theme-swatch theme-swatch--gold ${prefs.theme === 'gold' ? 'is-active' : ''}" data-theme="gold" title="Gold"></div>
              <div class="theme-swatch theme-swatch--midnight ${prefs.theme === 'midnight' ? 'is-active' : ''}" data-theme="midnight" title="Midnight"></div>
              <div class="theme-swatch theme-swatch--paper ${prefs.theme === 'paper' ? 'is-active' : ''}" data-theme="paper" title="Paper (light)"></div>
            </div>
          </div>
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Reduce motion</div>
              <div class="settings-row__sub">Disable breathing halos + transition animations. Respects accessibility preferences.</div>
            </div>
            <div class="toggle ${prefs.reduceMotion ? 'is-on' : ''}" data-pref-toggle="reduceMotion"></div>
          </div>
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Font weight</div>
              <div class="settings-row__sub">Lighter feels modern; heavier is more legible at small sizes.</div>
            </div>
            <select class="settings-select" data-pref-select="fontWeight">
              <option value="regular" ${prefs.fontWeight === 'regular' ? 'selected' : ''}>Regular</option>
              <option value="light" ${prefs.fontWeight === 'light' ? 'selected' : ''}>Light</option>
              <option value="medium" ${prefs.fontWeight === 'medium' ? 'selected' : ''}>Medium</option>
            </select>
          </div>
        </div>
      </section>
    `;
  }

  if (settingsTab === "security") {
    return `
      <section class="settings-section">
        <h2 class="settings-section__title">Security</h2>
        <div class="settings-section__sub">Password, auto-lock, seed backup.</div>
        <div class="settings-card">
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Lock wallet now</div>
              <div class="settings-row__sub">Clear the in-memory password and return to the unlock screen.</div>
            </div>
            <button class="ghost-button" id="lockNowBtn" style="width: auto; padding: 6px 14px;">Lock now</button>
          </div>
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Auto-lock</div>
              <div class="settings-row__sub">Lock the wallet automatically after idle period.</div>
            </div>
            <select class="settings-select" data-pref-select-num="autoLockMinutes">
              <option value="5"   ${prefs.autoLockMinutes === 5 ? 'selected' : ''}>5 minutes</option>
              <option value="15"  ${prefs.autoLockMinutes === 15 ? 'selected' : ''}>15 minutes</option>
              <option value="30"  ${prefs.autoLockMinutes === 30 ? 'selected' : ''}>30 minutes</option>
              <option value="60"  ${prefs.autoLockMinutes === 60 ? 'selected' : ''}>1 hour</option>
              <option value="0"   ${prefs.autoLockMinutes === 0 ? 'selected' : ''}>Never</option>
            </select>
          </div>
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Require password before sending</div>
              <div class="settings-row__sub">Always prompt for the password on Send / Swap.</div>
            </div>
            <div class="toggle ${prefs.requirePasswordOnSend ? 'is-on' : ''}" data-pref-toggle="requirePasswordOnSend"></div>
          </div>
          <div class="settings-row is-link" style="opacity: 0.55; cursor: not-allowed;">
            <div>
              <div class="settings-row__label">Change password <span class="pill-soon">SOON</span></div>
              <div class="settings-row__sub">Re-encrypts the wallet with a new password. Wallet UI flow ships in a later update; use the CLI today.</div>
            </div>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          </div>
          <div class="settings-row is-link" style="opacity: 0.55; cursor: not-allowed;">
            <div>
              <div class="settings-row__label">View seed phrase <span class="pill-soon">SOON</span></div>
              <div class="settings-row__sub">24 words. Recovery UI requires re-entering your password; ships in a later update.</div>
            </div>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          </div>
        </div>
      </section>
    `;
  }

  if (settingsTab === "network") {
    return `
      <section class="settings-section">
        <h2 class="settings-section__title">Network</h2>
        <div class="settings-section__sub">Which CoinCync node + Bitcoin Core endpoint to use. Active connection shown live on the dashboard's status dot.</div>
        <div class="settings-card">
          <div class="settings-row" style="opacity: 0.55;">
            <div>
              <div class="settings-row__label">CoinCync network <span class="pill-soon">SOON</span></div>
              <div class="settings-row__sub">Mainnet vs testnet switching requires a wallet restart and a fresh chain scan — flow ships in a later update.</div>
            </div>
            <select class="settings-select" disabled>
              <option selected>Testnet</option>
              <option>Mainnet (v1.0 launch — Oct 1, 2026)</option>
              <option>Regtest (local)</option>
            </select>
          </div>
          <div class="settings-row">
            <div>
              <div class="settings-row__label">CoinCync RPC endpoint</div>
              <div class="settings-row__sub">Currently connected to: <code>https://api.coincync.network/rpc/testnet</code></div>
            </div>
            <div class="settings-row__value">${state.connected ? "Connected" : "Reconnecting…"}</div>
          </div>
          <div class="settings-row" style="opacity: 0.55;">
            <div>
              <div class="settings-row__label">Bitcoin Core RPC (for Swap) <span class="pill-soon">v1.1</span></div>
              <div class="settings-row__sub">Local bitcoind connection for atomic swaps. Configuration UI ships with the cyncswap v1.1 release.</div>
            </div>
            <button class="ghost-button" style="width: auto; padding: 6px 14px; cursor: not-allowed;" disabled>Configure</button>
          </div>
          <div class="settings-row" style="opacity: 0.55;">
            <div>
              <div class="settings-row__label">Tor / SOCKS5 proxy <span class="pill-soon">SOON</span></div>
              <div class="settings-row__sub">Route node + swap traffic through Tor for IP privacy. Backend ready (SOCKS5 + DNS-over-TCP); UI wiring ships next.</div>
            </div>
            <div class="toggle" style="opacity: 0.6; cursor: not-allowed;"></div>
          </div>
        </div>
      </section>
    `;
  }

  if (settingsTab === "advanced") {
    return `
      <section class="settings-section">
        <h2 class="settings-section__title">Advanced</h2>
        <div class="settings-section__sub">For experienced users. Most options take effect on the next transaction.</div>
        <div class="settings-card">
          <div class="settings-row" style="opacity: 0.55;">
            <div>
              <div class="settings-row__label">Ring size <span class="pill-soon">SOON</span></div>
              <div class="settings-row__sub">CLSAG decoys per transaction. Default 11 is consensus-enforced minimum; tunable per-send UI ships in a later update.</div>
            </div>
            <select class="settings-select" disabled>
              <option>11 (default)</option><option>16</option><option>22</option><option>32</option>
            </select>
          </div>
          <div class="settings-row">
            <div>
              <div class="settings-row__label">Default fee tier</div>
              <div class="settings-row__sub">Pre-selected on the Send screen. You can still change per-send.</div>
            </div>
            <select class="settings-select" data-pref-select="defaultFeeTier">
              <option value="slow"   ${prefs.defaultFeeTier === 'slow' ? 'selected' : ''}>Slow</option>
              <option value="normal" ${prefs.defaultFeeTier === 'normal' ? 'selected' : ''}>Normal</option>
              <option value="fast"   ${prefs.defaultFeeTier === 'fast' ? 'selected' : ''}>Fast</option>
              <option value="flash"  ${prefs.defaultFeeTier === 'flash' ? 'selected' : ''}>Flash</option>
            </select>
          </div>
          <div class="settings-row" style="opacity: 0.55;">
            <div>
              <div class="settings-row__label">Show developer console <span class="pill-soon">SOON</span></div>
              <div class="settings-row__sub">Opens Tauri DevTools in the wallet window. Requires a backend command; ships in a later update.</div>
            </div>
            <div class="toggle" style="opacity: 0.6; cursor: not-allowed;"></div>
          </div>
        </div>
      </section>
    `;
  }

  if (settingsTab === "about") {
    // Pretty-truncate the wallet path so it fits the row without overflow.
    // Show the basename verbatim and middle-collapse longer parent dirs.
    const fmtPath = (p) => {
      if (!p) return "—";
      if (p.length <= 56) return p;
      const sep = p.includes("\\") ? "\\" : "/";
      const parts = p.split(sep);
      const tail = parts.slice(-2).join(sep);
      return parts[0] + sep + "…" + sep + tail;
    };
    return `
      <section class="settings-section">
        <h2 class="settings-section__title">About</h2>
        <div class="settings-section__sub">Build information, paths, and project links.</div>
        <div class="settings-card">
          <div class="settings-row">
            <div><div class="settings-row__label">Version</div><div class="settings-row__sub">CoinCync Wallet v2.0.0 alpha</div></div>
            <div class="settings-row__value">build a091e2c</div>
          </div>
          <div class="settings-row">
            <div><div class="settings-row__label">Check for updates</div><div class="settings-row__sub" id="updateStatus">Compare this build against the latest published release.</div></div>
            <button class="ghost-button" id="checkUpdateBtn" style="width: auto; padding: 6px 14px;">Check</button>
          </div>
          <div class="settings-row">
            <div><div class="settings-row__label">Wallet file</div><div class="settings-row__sub">${state.walletFilePath || "Not loaded — unlock first"}</div></div>
            <div class="settings-row__value" title="${state.walletFilePath || ""}">${fmtPath(state.walletFilePath)}</div>
          </div>
          <div class="settings-row">
            <div><div class="settings-row__label">Network</div><div class="settings-row__sub">Currently connected</div></div>
            <div class="settings-row__value">${state.connected ? `${state.network || "testnet"} · live` : "offline"}</div>
          </div>
          <div class="settings-row">
            <div><div class="settings-row__label">Chain tip</div><div class="settings-row__sub">Last seen block height</div></div>
            <div class="settings-row__value">${state.blockHeight ? state.blockHeight.toLocaleString() : "—"}</div>
          </div>
          <div class="settings-row is-link">
            <div><div class="settings-row__label">Project repository</div><div class="settings-row__sub">github.com/ghostrider1092/Coincync-Testnet-</div></div>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          </div>
          <div class="settings-row is-link">
            <div><div class="settings-row__label">Audit reports</div><div class="settings-row__sub">cyncswap audit prep + line coverage + mutation score</div></div>
            <svg class="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>
          </div>
        </div>
      </section>
    `;
  }

  return "";
}

function wireSettings() {
  // Tab nav
  app.querySelectorAll("[data-stab]").forEach(b => {
    b.addEventListener("click", () => {
      settingsTab = b.dataset.stab;
      renderShell();
    });
  });

  // Theme swatches — actually apply the theme + persist.
  app.querySelectorAll(".theme-swatch[data-theme]").forEach(s => {
    s.addEventListener("click", () => {
      app.querySelectorAll(".theme-swatch").forEach(x => x.classList.remove("is-active"));
      s.classList.add("is-active");
      setPref("theme", s.dataset.theme);
    });
  });

  // Toggles bound to a preference key.
  app.querySelectorAll("[data-pref-toggle]").forEach(t => {
    t.addEventListener("click", () => {
      const key = t.dataset.prefToggle;
      const next = !prefs[key];
      t.classList.toggle("is-on", next);
      setPref(key, next);
    });
  });

  // Selects bound to a preference key (string value).
  app.querySelectorAll("[data-pref-select]").forEach(s => {
    s.addEventListener("change", () => setPref(s.dataset.prefSelect, s.value));
  });

  // Selects bound to a preference key (numeric value — e.g., autoLockMinutes).
  app.querySelectorAll("[data-pref-select-num]").forEach(s => {
    s.addEventListener("change", () => setPref(s.dataset.prefSelectNum, parseInt(s.value, 10) || 0));
  });

  // Security → Lock now. lock_wallet clears the session password and emits
  // wallet_state; the wallet_state listener routes the UI back to unlock.
  const lockBtn = document.getElementById("lockNowBtn");
  if (lockBtn) {
    lockBtn.addEventListener("click", async () => {
      lockBtn.disabled = true;
      try {
        await invoke("lock_wallet");
        // Clear sensitive display state and route to the unlock screen —
        // the wallet_state event doesn't carry a locked flag, so drive the
        // transition client-side.
        state.balance = 0;
        state.balanceUnlocked = 0;
        state.address = "";
        state.transactions = [];
        showToast("Wallet locked", "success");
        renderUnlock();
      } catch (e) {
        showToast(`Lock failed: ${e.message || e}`, "error");
        lockBtn.disabled = false;
      }
    });
  }

  // About → Check for updates. check_for_update queries the release feed and
  // reports whether a newer build is available.
  const updateBtn = document.getElementById("checkUpdateBtn");
  const updateStatus = document.getElementById("updateStatus");
  if (updateBtn && updateStatus) {
    updateBtn.addEventListener("click", async () => {
      updateBtn.disabled = true;
      updateStatus.textContent = "Checking…";
      try {
        const info = await invoke("check_for_update");
        if (info && info.error) {
          updateStatus.textContent = `Check failed: ${info.error}`;
          updateStatus.style.color = "var(--text-tertiary)";
        } else if (info && info.available) {
          updateStatus.textContent = `Update available: ${info.latest || info.tag} (you have ${info.current})`;
          updateStatus.style.color = "var(--green)";
        } else if (info) {
          updateStatus.textContent = `Up to date (v${info.current})`;
          updateStatus.style.color = "var(--green)";
        }
      } catch (e) {
        updateStatus.textContent = `Check failed: ${e.message || e}`;
        updateStatus.style.color = "var(--text-tertiary)";
      }
      updateBtn.disabled = false;
    });
  }
}

// ─── Addresses ────────────────────────────────────────────────────
// Address book is persisted to localStorage (key: coincync-addressbook).
// No mock contacts; users add their own.
function loadAddressBook() {
  try {
    const raw = localStorage.getItem("coincync-addressbook");
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) { return []; }
}

function addressesHtml() {
  const book = loadAddressBook();

  if (book.length === 0) {
    return `
      <header class="main__header">
        <div>
          <h1 class="main__title">Addresses</h1>
          <div class="main__subtitle">Saved address book · local-only · never leaves your device</div>
        </div>
        <button class="primary-button" style="width: auto; padding: 12px 24px; margin-top: 0;" disabled
                title="Address-book add UI ships in a later update">+ Add address <span class="pill-soon">SOON</span></button>
      </header>
      <div class="tools-page">
        <div class="activity-empty">
          <div class="activity-empty__art">${ICONS.addresses || ICONS.arrowDown}</div>
          <div class="activity-empty__title">No saved addresses yet</div>
          <div class="activity-empty__body">
            Your address book lives locally and stays on this device. When you Send or Receive, the addresses you use will land here automatically — or you can add them manually once that UI ships.
          </div>
        </div>
      </div>
    `;
  }

  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Addresses</h1>
        <div class="main__subtitle">${book.length} saved · book is local-only · never leaves your device</div>
      </div>
      <button class="primary-button" style="width: auto; padding: 12px 24px; margin-top: 0;">+ Add address</button>
    </header>
    <div class="tools-page">
      <div class="addresses-grid">
        ${book.map(a => `
          <div class="address-card">
            <div class="address-card__head">
              <div>
                <div class="address-card__label">${a.label}</div>
                <span class="address-card__tag ${a.tagClass}">${a.tag}</span>
              </div>
              <button class="address-card__menu" title="More">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="1.5"/><circle cx="12" cy="5" r="1.5"/><circle cx="12" cy="19" r="1.5"/></svg>
              </button>
            </div>
            <div class="address-card__address">${a.addr}</div>
            <div class="address-card__meta">
              <span>Added ${a.added}</span>
              <span>Last used ${a.lastUsed}</span>
            </div>
            <div class="address-card__actions">
              <button class="icon-button is-primary" title="Send to">${ICONS.send}</button>
              <button class="icon-button" title="Copy">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
              </button>
              <button class="icon-button" title="QR">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
              </button>
              <button class="icon-button" title="Edit">
                <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 1 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
              </button>
            </div>
          </div>
        `).join("")}
      </div>
    </div>
  `;
}

// ─── Mining ───────────────────────────────────────────────────────
// `samples` is a client-side ring of recent hashrate readings (one per
// mining_stats tick, ~3 s apart) driving the hero sparkline + avg/peak.
// `startedAt` is the wall-clock ms the current mining session began,
// for the live uptime readout. Both are frontend-only — no backend
// plumbing — so they work today against the existing 3 s event stream.
let mining = {
  on: false, threads: 4, hashrate: 0, blocks: 0, blocksThisSession: 0,
  algorithm: "RandomX", samples: [], peak: 0, startedAt: 0,
};

// How many hashrate samples to retain for the sparkline. At ~3 s per
// tick, 40 samples ≈ 2 minutes of visible trend.
const MINING_SAMPLE_CAP = 40;

/// Push a hashrate reading into the sparkline ring, evicting the oldest
/// past the cap, and track the session peak.
function recordHashrateSample(hps) {
  if (typeof hps !== "number" || !isFinite(hps)) return;
  mining.samples.push(hps);
  if (mining.samples.length > MINING_SAMPLE_CAP) mining.samples.shift();
  if (hps > mining.peak) mining.peak = hps;
}

// ─── User preferences (persisted to localStorage) ─────────────────
// Applied at boot before the splash so there's no flash of wrong theme.
// Each preference: load → apply class to <html> → also write to localStorage on change.
const PREFS_KEY = "coincync-prefs";
const DEFAULT_PREFS = {
  theme: "dark",          // dark | gold | midnight | paper
  reduceMotion: false,
  fontWeight: "regular",  // regular | light | medium
  autoLockMinutes: 15,
  requirePasswordOnSend: true,
  defaultFeeTier: "normal", // slow | normal | fast | flash
};

function loadPrefs() {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return { ...DEFAULT_PREFS };
    return { ...DEFAULT_PREFS, ...JSON.parse(raw) };
  } catch (e) { return { ...DEFAULT_PREFS }; }
}

function savePrefs(prefs) {
  try { localStorage.setItem(PREFS_KEY, JSON.stringify(prefs)); }
  catch (e) { console.warn("[prefs] save failed:", e); }
}

function applyPrefs(prefs) {
  const html = document.documentElement;
  // Theme — strip all theme-* classes, add the one selected.
  ["dark", "gold", "midnight", "paper"].forEach(t => html.classList.remove(`theme-${t}`));
  if (prefs.theme && prefs.theme !== "dark") html.classList.add(`theme-${prefs.theme}`);
  // Reduce motion
  html.classList.toggle("reduce-motion", !!prefs.reduceMotion);
  // Font weight
  ["light", "medium"].forEach(w => html.classList.remove(`fw-${w}`));
  if (prefs.fontWeight === "light") html.classList.add("fw-light");
  if (prefs.fontWeight === "medium") html.classList.add("fw-medium");
}

let prefs = loadPrefs();
applyPrefs(prefs);

// Update + persist + re-apply.
function setPref(key, value) {
  prefs[key] = value;
  savePrefs(prefs);
  applyPrefs(prefs);
}

// Toast queue — used by block_found notifications + send-result feedback.
// `kind`: omit for the default gold-tinted info style; "success" / "error"
// tint via the `.is-success` / `.is-error` modifier classes (see shell.css).
// Multi-line msgs OK — the toast wraps and grows vertically.
function showToast(msg, kind) {
  const id = "miningToast";
  let toast = document.getElementById(id);
  if (!toast) {
    toast = document.createElement("div");
    toast.id = id;
    toast.className = "mining-toast";
    document.body.appendChild(toast);
  }
  // Reset modifier classes from any prior call.
  toast.classList.remove("is-success", "is-error");
  if (kind === "success") toast.classList.add("is-success");
  if (kind === "error")   toast.classList.add("is-error");
  toast.textContent = msg;
  toast.classList.add("is-visible");
  clearTimeout(toast._hideTimer);
  // Errors stay up a little longer so the user can read what failed.
  const dwellMs = kind === "error" ? 7000 : 4500;
  toast._hideTimer = setTimeout(() => toast.classList.remove("is-visible"), dwellMs);
}

// Back-compat alias — `showMiningToast` is the prior name + still used
// by the block_found subscription. Keep both pointing at the same impl.
function showMiningToast(msg) { showToast(msg); }

// Render recent hashrate samples as an inline SVG sparkline: a gold
// stroke over a faint area fill with an emphasized endpoint. Pure
// client-side, no dependency. Returns "" until there are ≥2 samples so
// we draw nothing rather than a misleading flat line.
function hashrateSparkline(samples) {
  const pts = (samples || []).filter((n) => typeof n === "number" && isFinite(n));
  if (pts.length < 2) return "";
  const W = 300, H = 46, PAD = 4;
  const min = Math.min(...pts);
  const max = Math.max(...pts);
  const span = max - min || 1;
  const stepX = (W - PAD * 2) / (pts.length - 1);
  const xy = pts.map((v, i) => {
    const x = PAD + i * stepX;
    const y = PAD + (H - PAD * 2) * (1 - (v - min) / span);
    return [x, y];
  });
  const line = xy
    .map(([x, y], i) => `${i === 0 ? "M" : "L"}${x.toFixed(1)} ${y.toFixed(1)}`)
    .join(" ");
  const last = xy[xy.length - 1];
  const area = `${line} L${last[0].toFixed(1)} ${H - PAD} L${xy[0][0].toFixed(1)} ${H - PAD} Z`;
  return `
    <svg class="mining-spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--gold-400)" stop-opacity="0.26"/>
          <stop offset="100%" stop-color="var(--gold-400)" stop-opacity="0"/>
        </linearGradient>
      </defs>
      <path d="${area}" fill="url(#sparkFill)" stroke="none"/>
      <path d="${line}" fill="none" stroke="var(--gold-400)" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round"/>
      <circle cx="${last[0].toFixed(1)}" cy="${last[1].toFixed(1)}" r="2.6" fill="var(--gold-300)"/>
    </svg>`;
}

// mm:ss (or hh:mm:ss past an hour) for the live session uptime.
function fmtUptime(startedAtMs) {
  if (!startedAtMs) return "00:00";
  const s = Math.max(0, Math.floor((Date.now() - startedAtMs) / 1000));
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), sec = s % 60;
  const p = (n) => String(n).padStart(2, "0");
  return h > 0 ? `${p(h)}:${p(m)}:${p(sec)}` : `${p(m)}:${p(sec)}`;
}

// Session-average hashrate over the retained sample ring.
function avgHashrate(samples) {
  const pts = (samples || []).filter((n) => typeof n === "number" && isFinite(n));
  if (!pts.length) return 0;
  return pts.reduce((a, b) => a + b, 0) / pts.length;
}

function miningHtml() {
  const hr = mining.on ? mining.hashrate : 0;
  // "Address ready" = unlocked wallet has loaded a real address (not empty, not the dev-preview placeholder).
  // Mining is blocked at the backend on this same condition; surfacing it
  // in the UI prevents the user from hitting Start and getting a typed error.
  const addr = state.address || "";
  const addressReady = addr.length >= 16 && !addr.startsWith("tCYNCxq8a4f1m12k7q4j");
  // Earned-this-session estimate: 1 tCYNC per block (current testnet
  // reward; replace with chain-pulled value once block-reward RPC is
  // wired). Conservative placeholder so the panel reads honest, not magic.
  const earnedThisSession = (mining.blocksThisSession * 1.0).toFixed(6);
  const networkHeight = state.blockHeight
    ? state.blockHeight.toLocaleString()
    : "—";
  const networkSub = state.connected
    ? (state.syncPct >= 100 ? "Synced · 0 blocks behind" : `${state.syncPct.toFixed(1)}% synced`)
    : "Node offline";
  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Mining</h1>
        <div class="main__subtitle">RandomX CPU mining · Solo · canonical retail miner</div>
      </div>
    </header>
    <div class="tools-page">
      ${!addressReady ? `
        <div class="future-banner" style="border-left-color: var(--amber); background: linear-gradient(135deg, rgba(255,201,96,0.12) 0%, transparent 60%), var(--glass-light);">
          <div class="future-banner__icon" style="background: rgba(255,201,96,0.18); border-color: var(--amber); color: var(--amber);">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <div class="future-banner__body">
            <div class="future-banner__chip" style="color: var(--amber); border-color: var(--amber); background: rgba(255,201,96,0.12);">Unlock first</div>
            <div class="future-banner__title">Unlock your wallet to start mining</div>
            <div class="future-banner__text">
              Coinbase rewards land at your wallet's address. We need an unlocked wallet to load the address — mining to a placeholder would lose the rewards. Unlock from the splash, or restore from your seed phrase if this is a fresh install.
            </div>
          </div>
        </div>
      ` : ""}

      <section class="mining-hero">
        <div class="mining-status ${mining.on ? "is-on" : ""}">
          <div class="mining-status__dot"></div>
          <span>${mining.on ? "Mining" : "Idle"}</span>
        </div>
        <div>
          <span class="mining-hashrate" id="hashrateValue">${hr.toFixed(1)}</span>
          <span class="mining-hashrate__unit">H/s</span>
        </div>
        ${mining.on ? hashrateSparkline(mining.samples) : ""}
        <div class="mining-sub">
          ${mining.on
            ? `${mining.algorithm} · ${mining.threads} thread${mining.threads !== 1 ? "s" : ""} · avg ${avgHashrate(mining.samples).toFixed(1)} · peak ${mining.peak.toFixed(1)} H/s`
            : `Press start to begin mining · ${mining.threads} thread${mining.threads !== 1 ? "s" : ""} configured · ${mining.algorithm}`}
        </div>
      </section>

      <section class="mining-stats">
        <div class="mining-stat">
          <div class="mining-stat__label">Blocks found</div>
          <div class="mining-stat__value">${mining.blocksThisSession}</div>
          <div class="mining-stat__sub">+${earnedThisSession} ${state.unit} est. this session</div>
        </div>
        <div class="mining-stat">
          <div class="mining-stat__label">Session</div>
          <div class="mining-stat__value" style="font-feature-settings: 'tnum';">${mining.on ? fmtUptime(mining.startedAt) : "—"}</div>
          <div class="mining-stat__sub">${mining.on ? "Uptime this session" : "Idle"}</div>
        </div>
        <div class="mining-stat">
          <div class="mining-stat__label">Network height</div>
          <div class="mining-stat__value">${networkHeight}</div>
          <div class="mining-stat__sub">${networkSub}</div>
        </div>
        <div class="mining-stat">
          <div class="mining-stat__label">Peers</div>
          <div class="mining-stat__value">${state.peerCount}</div>
          <div class="mining-stat__sub">${state.connected ? "Connected to network" : "Reconnecting…"}</div>
        </div>
      </section>

      <section class="mining-controls">
        <div class="threads-row">
          <div class="threads-row__label">
            <span>Threads</span>
            <span id="threadsLabel">${mining.threads} of 16 available</span>
          </div>
          <input type="range" class="threads-slider" min="1" max="16" value="${mining.threads}" id="threadsSlider" />
        </div>
        <button class="primary-button" id="mineToggle"
          style="width: auto; padding: 14px 36px; margin-top: 0; ${!addressReady && !mining.on ? "opacity: 0.5; cursor: not-allowed;" : ""}"
          ${!addressReady && !mining.on ? "disabled" : ""}>
          ${mining.on ? "Stop mining" : (addressReady ? "Start mining" : "Unlock wallet first")}
        </button>
      </section>
    </div>
  `;
}

function wireMining() {
  const slider = document.getElementById("threadsSlider");
  const label = document.getElementById("threadsLabel");
  if (slider) {
    slider.addEventListener("input", () => {
      mining.threads = +slider.value;
      label.textContent = `${mining.threads} of 16 available`;
    });
  }
  const btn = document.getElementById("mineToggle");
  if (btn) {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      try {
        if (mining.on) {
          await invoke("stop_mining");
          mining.on = false;
          mining.hashrate = 0;
          mining.startedAt = 0;
        } else {
          // The wallet's real address (loaded by primeWalletState from
          // get_wallet_address). NO PLACEHOLDER FALLBACK — mining to a
          // bogus address means lost coinbase rewards, so fail loudly
          // instead of silently sending blocks to a dead key.
          const addr = state.address || "";
          if (!addr || addr.startsWith("tCYNCxq8a4f1m12k7q4j") || addr.length < 16) {
            showToast("Unlock your wallet first — mining needs your real address loaded.", "error");
            btn.disabled = false;
            return;
          }
          await invoke("start_mining", {
            address: addr,
            threads: mining.threads,
          });
          mining.on = true;
          // Start the uptime clock + clear the prior trend immediately so
          // the panel reads live before the first mining_stats tick.
          mining.startedAt = Date.now();
          mining.samples = [];
          mining.peak = 0;
          // mining_stats event updates the display reactively — no polling needed
        }
        renderShell();
      } catch (e) {
        showToast(`Mining toggle failed: ${e.message || e}`, "error");
      }
      btn.disabled = false;
    });
  }
}

let miningPollId = null;
function pollMiningStats() {
  if (miningPollId) clearInterval(miningPollId);
  miningPollId = setInterval(async () => {
    if (!mining.on) { clearInterval(miningPollId); return; }
    try {
      const s = await invoke("get_mining_stats");
      if (s) {
        mining.hashrate = s.hashrate || 0;
        const el = document.getElementById("hashrateValue");
        if (el) el.textContent = (mining.hashrate || 0).toFixed(1);
      }
    } catch {}
  }, 2000);
}

// ─── Multi-sig ────────────────────────────────────────────────────
let msStage = "gen";

const MS_STAGES = [
  { id: "gen",       num: 1, label: "Generate" },
  { id: "info",      num: 2, label: "Share info" },
  { id: "round1",    num: 3, label: "Round 1" },
  { id: "round2",    num: 4, label: "Round 2" },
  { id: "aggregate", num: 5, label: "Aggregate" },
  { id: "send",      num: 6, label: "Send" },
];

function multisigHtml() {
  return `
    <header class="main__header">
      <div>
        <h1 class="main__title">Multi-sig</h1>
        <div class="main__subtitle">FROST M-of-N threshold signing · CIP-008</div>
      </div>
    </header>
    <div class="tools-page">
      <div class="future-banner">
        <div class="future-banner__icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="future-banner__body">
          <div class="future-banner__chip">Future update</div>
          <div class="future-banner__title">Multi-sig coordinator UI in progress</div>
          <div class="future-banner__text">
            <strong>FROST M-of-N threshold signing</strong> (CIP-008) is supported at the protocol level today; the desktop wallet's coord-session UI ships in a later update. Operators who need multi-sig before then can use the <code>coord-cli</code> binary directly. The UI below is the design scaffolding — buttons are inert until cutover.
          </div>
        </div>
      </div>
      <div class="multisig-stages swap-stages">
        ${MS_STAGES.map(s => `
          <button class="swap-stage ${s.id === msStage ? "is-active" : ""}" data-msstage="${s.id}">
            <div class="swap-stage__num">${s.num}</div>
            <div class="swap-stage__name">${s.label}</div>
          </button>
        `).join("")}
      </div>
      ${multisigStageHtml()}
    </div>
  `;
}

function multisigStageHtml() {
  if (msStage === "gen") {
    return `
      <div class="multisig-card">
        <h3 class="multisig-card__title">Generate M-of-N key shares</h3>
        <p class="multisig-card__sub">
          Creates N share files (one per participant). Any M of them can later collaborate to sign a transaction; fewer than M cannot. The cryptography is FROST-ed25519 (Zcash Foundation reference implementation).
        </p>
        <div class="mn-config">
          <div class="field-group">
            <div class="field-label"><span>Threshold (M)</span><span class="field-label__hint">Minimum signers</span></div>
            <div class="field-input"><input type="text" placeholder="2" inputmode="numeric"/></div>
          </div>
          <div class="field-group">
            <div class="field-label"><span>Total (N)</span><span class="field-label__hint">Participants</span></div>
            <div class="field-input"><input type="text" placeholder="3" inputmode="numeric"/></div>
          </div>
        </div>
        <div class="field-group">
          <div class="field-label"><span>Output directory</span><span class="field-label__hint">Absolute path · created if missing</span></div>
          <div class="field-input"><input type="text" placeholder="C:\\Users\\you\\multisig-session-1\\"/></div>
        </div>
        <button class="primary-button" style="margin-top: var(--sp-5);">Generate shares</button>
      </div>
    `;
  }
  const labels = { info: "Share Info", round1: "Round 1: commitments", round2: "Round 2: shares", aggregate: "Aggregate signature", send: "Send signed transaction" };
  return `
    <div class="multisig-card">
      <h3 class="multisig-card__title">${labels[msStage]}</h3>
      <p class="multisig-card__sub">
        ${msStage === "info"     ? "Inspect a share file to see its index, threshold, total, and the corresponding public key the FROST protocol will produce."
        : msStage === "round1"  ? "Each signer generates a one-time commitment + secret nonce. Commitments are shared with the other participants; nonces stay local."
        : msStage === "round2"  ? "Each signer combines: commitments + the message to sign + their share + their nonce. Output: a partial signature share."
        : msStage === "aggregate" ? "Combine M signature shares + the key-shares pubkeys + the message into the final FROST signature."
        : "Submit the aggregated signature to a CoinCync node via the standard send_raw_transaction path."}
      </p>
      <div class="swap-empty">Form lands when this slice is wired. Visual scaffold + Tauri command path already mirrored from v1.</div>
    </div>
  `;
}

function wireMultisig() {
  app.querySelectorAll("[data-msstage]").forEach(b => {
    b.addEventListener("click", () => {
      msStage = b.dataset.msstage;
      renderShell();
    });
  });
}

// ─── Placeholder for not-yet-built pages ──────────────────────────
function placeholderHtml(title, hint) {
  return `
    <div class="dashboard">
      <header class="main__header">
        <div>
          <h1 class="main__title">${title}</h1>
          <div class="main__subtitle">Coming next</div>
        </div>
      </header>
      <div class="hero-balance" style="text-align: center; padding: var(--sp-16);">
        <div class="hero-balance__label">${title}</div>
        <div style="margin-top: var(--sp-4); font-family: var(--font-mono); font-size: var(--fs-sm); color: var(--text-tertiary); line-height: var(--lh-relaxed); max-width: 420px; margin-inline: auto;">
          ${hint}
        </div>
      </div>
    </div>
  `;
}

// ─── Boot ─────────────────────────────────────────────────────────
// Subscribe to push events BEFORE the splash renders so we catch
// updates from the moment the Rust app starts emitting (the chain-state
// poller starts at Tauri app setup, which can fire before the JS bundle
// finishes loading — subscribing early closes the race).
subscribeToChainState();
subscribeToWalletState();
subscribeToMiningStats();
renderSplash();
