/* CyncHub — standalone desktop app (frontend).
   Its own codebase. In the Tauri app every screen reads live data from the
   bundled coincync-node RPC + coincync-wallet CLI; in a plain browser it
   falls back to a small mock so the design still previews. */

const $ = s => document.querySelector(s);
const view = $("#view");
let current = "vault";

// ── backend bridge ──────────────────────────────────────────────────
// Real data in the CyncHub desktop app (Tauri); illustrative mock in a
// plain browser so the design preview still works. Same UI either way.
const IS_TAURI = typeof window !== "undefined" && !!window.__TAURI__;
async function invoke(cmd, args){
  if (IS_TAURI){
    const t = window.__TAURI__;
    const inv = (t.core && t.core.invoke) || (t.tauri && t.tauri.invoke) || t.invoke;
    return await inv(cmd, args);
  }
  return mockInvoke(cmd, args);
}
function mockInvoke(cmd){
  switch(cmd){
    case "get_chain_info": return { connected:true, height:1068, isSynced:false, peers:4, targetHeight:25258, anonSet:1069, ringSize:11, status:"syncing", network:"testnet", supply:52786.07, tipAgeSecs:0 };
    case "get_metrics": { const h=25633, now=Math.floor(Date.now()/1000); return { connected:true, height:h, peers:5, targetHeight:h, isSynced:true, difficulty:131072, netHashrate:1092, mempool:1, supply:52786.07, anonSet:1069, ringSize:16, tipAgeSecs:34, avgBlockSecs:112, blocks:Array.from({length:8},(_,k)=>({height:h-k, timestamp:now-k*112-30, txCount:k===1?1:0})) }; }
    case "wallet_exists":  return true;
    case "scan_wallet":    return { total:0, unlocked:0, height:1068, utxoCount:0 };
    case "get_wallet_address": return "cync1q…demo…x0qT9";
    case "disclose_balance":   return { kind:"balance", artifact:"zkCYNC1"+"deadbeefcafef00d".repeat(10) };
    case "disclose_scoped_view_key": return { kind:"scoped-view-key", artifact: JSON.stringify({from:0,to:S.tip,view_secret:"f805b0…",view_public:"866012…"}) };
    case "send_transaction":   return "mock"+"deadbeef".repeat(8);
    case "validate_address":   return { valid:true, network:"testnet", kind:"Standard", paymentId:false };
    case "new_subaddress":     return "tCYNCsub"+"1a2b3c".repeat(6)+"demo";
    case "integrated_address": return "tCYNCint"+"9f8e7d".repeat(6)+"demo";
    case "list_received":      return [];
    case "reveal_seed":        return "useful burger waste abuse risk injury crowd tiny squirrel calm step brand lyrics tomato floor review render behave inner plug produce pulse feel garage".split(" ");
    case "app_health":         return { nodeBin:true, walletBin:true, rigBin:true, rpcKey:true, walletExists:true, dataDir:"%APPDATA%/coincync/cynchub-node", version:"0.1.0" };
    case "node_status":        return { running:true, managed:false, binAvailable:true, height:1068, targetHeight:25258, isSynced:false, peers:4, progress:1068/25258, phase:"Syncing 1,068 / 25,258" };
    case "start_node":         return { running:true, managed:true, binAvailable:true, height:0, targetHeight:0, isSynced:false, peers:0, progress:0, phase:"Starting…" };
    case "stop_node":          return { running:false, managed:false, binAvailable:true, height:0, targetHeight:0, isSynced:false, peers:0, progress:0, phase:"Stopped" };
    case "shielded_balance":   return { balance:0, notes:0, active:false };
    case "shield_funds":       return "mock"+"feedface".repeat(8);
    case "unshield_funds":     return "mock"+"feedface".repeat(8);
    case "start_churn":        return { running:true };
    case "stop_churn":         return { running:false };
    case "churn_status":       return { running:false };
    case "mining_status":      return { mining:false, threads:7, hashrate:0, blocksFound:0, maxThreads:16, rigAvailable:true, mode:"solo", poolUrl:"", sharesAccepted:0, sharesRejected:0, difficulty:131072, netHashrate:1092, estSoloSecs:0, recommend:"measuring" };
    case "start_mining":       return { mining:true, threads:7, hashrate:0, blocksFound:0, maxThreads:16, rigAvailable:true, mode:(S.minerMode==="pool"?"pool":"solo"), poolUrl:S.poolUrl||"", sharesAccepted:0, sharesRejected:0, difficulty:131072, netHashrate:1092, estSoloSecs:0, recommend:"measuring" };
    case "stop_mining":        return { mining:false, threads:7, hashrate:0, blocksFound:0, maxThreads:16, rigAvailable:true, mode:"solo", poolUrl:"", sharesAccepted:0, sharesRejected:0, difficulty:131072, netHashrate:1092, estSoloSecs:0, recommend:"measuring" };
    default: return null;
  }
}

// ── icons ──────────────────────────────────────────────────────────
const I = {
  up:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 19V5M12 5l-6 6M12 5l6 6"/></svg>`,
  down:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 5v14M12 19l6-6M12 19l-6-6"/></svg>`,
  shield:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/><path d="M9 12l2 2 4-4"/></svg>`,
  shieldPlain:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 3l8 4v5c0 5-3.5 8-8 9-4.5-1-8-4-8-9V7z"/></svg>`,
  eye:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>`,
  circle:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="9"/></svg>`,
  lock:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/></svg>`,
  unshield:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M4 8h13l-3-3M20 16H7l3 3"/></svg>`,
  check:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M20 6L9 17l-5-5"/></svg>`,
  clock:`<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.7"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>`,
};

// ── live state (populated from the node + wallet; zero/null until then) ─
const FORK = 29000; // shielded pool activates at this testnet height
const S = {
  unit: "tCYNC",
  // wallet — from scan_wallet; all zero until a real wallet is scanned
  total: 0, transparent: 0, shielded: 0, pending: 0,
  utxoCount: 0, address: "", scannedHeight: 0, scanned: false,
  // chain — from get_chain_info; null until the first poll returns
  tip: null, peers: null, target: null, anonSet: null, ringSize: null,
  supply: null, status: "connecting", connected: false, network: "",
  // mining — from mining_status; drives the bundled coincync-rig
  mining: { mining:false, threads:0, hashrate:0, blocksFound:0,
            maxThreads:(typeof navigator!=="undefined"&&navigator.hardwareConcurrency)||4, rigAvailable:true,
            mode:"solo", poolUrl:"", sharesAccepted:0, sharesRejected:0, difficulty:0, netHashrate:0, estSoloSecs:0, recommend:"measuring" },
  minerThreads: Math.max(1, (((typeof navigator!=="undefined"&&navigator.hardwareConcurrency)||4) - 1)),
  minerMode: "auto",   // user choice: "solo" | "pool" | "auto" (smart routing)
  poolUrl: "",         // stratum pool host:port for pool mode
  autoSwitchedTo: "",  // last mode auto-routing moved us to (avoids flapping)
  // node — from node_status; drives the bundled coincync-node
  node: { running:false, managed:false, binAvailable:true, height:0, targetHeight:0,
          isSynced:false, peers:0, progress:0, phase:"—" },
  // shielded pool — from shielded_balance (0 until the h29000 fork)
  shieldedNotes: 0, shieldedActive: false,
  // auto-churn (ghost mode) running state
  churnOn: false,
};
const f = n => Number(n || 0).toFixed(2);
const num = n => (n == null ? "—" : Number(n).toLocaleString());

// ── theme + auto-lock (persisted per-device in localStorage) ─────────
function lsGet(k, d){ try { const v = localStorage.getItem(k); return v==null ? d : v; } catch { return d; } }
function lsSet(k, v){ try { localStorage.setItem(k, String(v)); } catch {} }
const THEMES = [
  { id:"dark", label:"Dark" },
  { id:"light", label:"Light" },
  { id:"system", label:"System" },
  { id:"midnight", label:"Midnight" },
  { id:"slate", label:"Slate" },
  { id:"oled", label:"OLED" },
  { id:"sepia", label:"Sepia" },
  { id:"nord", label:"Nord" },
  { id:"mocha", label:"Mocha" },
  { id:"rose", label:"Rosé" },
  { id:"gruvbox", label:"Gruvbox" },
  { id:"solarized-light", label:"Solarized" },
  { id:"contrast", label:"High-contrast" },
];
const THEME_IDS = THEMES.map(t => t.id);
function getTheme(){ const t = lsGet("cynchub.theme","dark"); return THEME_IDS.includes(t) ? t : "dark"; }
// "system" resolves to dark/light from the OS; others map straight to a palette.
function resolveTheme(t){ if (t === "system"){ return (window.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches) ? "dark" : "light"; } return t; }
function applyTheme(t){ if (!THEME_IDS.includes(t)) t = "dark"; document.documentElement.setAttribute("data-theme", resolveTheme(t)); }
function setTheme(t){ if (!THEME_IDS.includes(t)) t = "dark"; lsSet("cynchub.theme", t); applyTheme(t); }

// Cosmetic toggles — each sets (or clears) a data-* attribute on <html>; the CSS
// does the rest. All flat & clean: density, motion, UI font, corner style.
const UIPREFS = {
  density: { ls:"cynchub.density", def:"comfortable", attr:"data-density", on:v => v==="compact" ? "compact" : null },
  motion:  { ls:"cynchub.motion",  def:"full",        attr:"data-motion",  on:v => v==="reduce" ? "reduce" : null },
  font:    { ls:"cynchub.font",    def:"system",      attr:"data-font",    on:v => (v==="rounded"||v==="grotesk") ? v : null },
  corners: { ls:"cynchub.corners", def:"round",       attr:"data-corners", on:v => v==="sharp" ? "sharp" : null },
};
function getPref(k){ return lsGet(UIPREFS[k].ls, UIPREFS[k].def) || UIPREFS[k].def; }
function applyPref(k){ const p = UIPREFS[k]; const val = p.on(getPref(k)); if (val) document.documentElement.setAttribute(p.attr, val); else document.documentElement.removeAttribute(p.attr); }
function setPref(k, v){ lsSet(UIPREFS[k].ls, v); applyPref(k); }
function applyAllUiPrefs(){ Object.keys(UIPREFS).forEach(applyPref); }

// Accent customization — overrides the theme's accent (--gold) independently.
// Stored value is "theme" (use the theme's own accent) or a hex color; the
// lighter companion (--gold-200) is derived so any color stays cohesive.
const ACCENT_PRESETS = [
  { label:"Theme",   color:null },
  { label:"Gold",    color:"#d9a24e" },
  { label:"Amber",   color:"#f0a93a" },
  { label:"Emerald", color:"#27bd83" },
  { label:"Teal",    color:"#1fb6c4" },
  { label:"Azure",   color:"#4f8ff0" },
  { label:"Indigo",  color:"#8b7bf0" },
  { label:"Rose",    color:"#eb5d97" },
  { label:"Coral",   color:"#f0744a" },
];
const DEFAULT_ACCENT = "#d4a059";
function isHexColor(s){ return typeof s === "string" && /^#[0-9a-fA-F]{6}$/.test(s); }
function lightenHex(hex, amt){
  const n = parseInt(hex.slice(1), 16);
  let r = (n>>16)&255, g = (n>>8)&255, b = n&255;
  r = Math.round(r + (255-r)*amt); g = Math.round(g + (255-g)*amt); b = Math.round(b + (255-b)*amt);
  return "#" + ((1<<24) + (r<<16) + (g<<8) + b).toString(16).slice(1);
}
function getAccent(){ const a = lsGet("cynchub.accent","theme"); return isHexColor(a) ? a.toLowerCase() : "theme"; }
function currentAccentColor(){ const a = getAccent(); return isHexColor(a) ? a : DEFAULT_ACCENT; }
function applyAccent(v){
  const r = document.documentElement.style;
  if (!isHexColor(v)){ r.removeProperty("--gold"); r.removeProperty("--gold-200"); }
  else { r.setProperty("--gold", v); r.setProperty("--gold-200", lightenHex(v, 0.28)); }
}
function setAccent(v){ const val = isHexColor(v) ? v.toLowerCase() : "theme"; lsSet("cynchub.accent", val); applyAccent(val); }

// Address book — saved recipients (per device, localStorage).
function getContacts(){ try { return JSON.parse(lsGet("cynchub.contacts","[]")) || []; } catch { return []; } }
function saveContacts(cs){ lsSet("cynchub.contacts", JSON.stringify(cs)); }
function addContact(label, address){ const cs = getContacts().filter(c => c.address !== address); cs.unshift({ label, address }); saveContacts(cs.slice(0, 30)); }
function removeContact(address){ saveContacts(getContacts().filter(c => c.address !== address)); }

// Sent-transaction log — the CLI doesn't record outgoing sends, so CyncHub
// remembers the ones it submits (per device) to build a full history alongside
// the on-chain received outputs. No amounts leave the device.
function getSentLog(){ try { return JSON.parse(lsGet("cynchub.sentlog","[]")) || []; } catch { return []; } }
function recordSend(e){ const l = getSentLog(); l.unshift(e); lsSet("cynchub.sentlog", JSON.stringify(l.slice(0, 60))); }
// Export the unified history (sent-log + received outputs) as CSV, for records.
async function exportHistoryCsv(){
  let recv = [];
  if (IS_TAURI){ try { recv = (await invoke("list_received")) || []; } catch(e){} }
  const sent = getSentLog();
  const esc = (s) => { s = String(s==null?"":s); return /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s; };
  const rows = [["Type","Amount (CYNC)","Counterparty / Output","Block","Date","TxID","Memo/Status"]];
  sent.forEach(s => rows.push(["Sent", Number(s.amount).toFixed(6), s.address||"", s.height||"", s.ts?new Date(s.ts).toISOString().slice(0,10):"", s.txid||"", s.memo||""]));
  recv.forEach(r => rows.push(["Received", Number(r.amount).toFixed(6), r.txOut||"", r.height||"", "", "", r.spent?"spent":"confirmed"]));
  if (rows.length === 1){ showToast(`<b>Nothing to export yet</b><br>No sends or received outputs recorded.`, ""); return; }
  const csv = rows.map(r => r.map(esc).join(",")).join("\r\n");
  try {
    const u = URL.createObjectURL(new Blob([csv], { type:"text/csv" }));
    const a = document.createElement("a"); a.href = u; a.download = `cynchub-history-${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(()=>URL.revokeObjectURL(u), 800);
    showToast(`<b>History exported</b><br>${rows.length-1} transactions saved as CSV.`, "");
  } catch(e){ showToast(`<b>Export failed</b><br>${String((e&&e.message)||e)}`, ""); }
}
function getAutoLock(){ const n = parseInt(lsGet("cynchub.autolock","15"),10); return Number.isFinite(n) && n>=0 ? n : 15; } // minutes; 0 = off
function setAutoLock(m){ lsSet("cynchub.autolock", m); armIdleLock(); }
applyTheme(getTheme());
applyAccent(getAccent());
applyAllUiPrefs();
// keep a "System" theme in step with the OS light/dark switch
if (window.matchMedia){ try { matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => { if (getTheme() === "system") applyTheme("system"); }); } catch {} }

// ── toasts (incoming-payment + status alerts) ──────────────────────
const toastEl = (() => { const d = document.createElement("div"); d.className = "toasts"; if (typeof document!=="undefined" && document.body) document.body.appendChild(d); return d; })();
function showToast(html, kind){
  if (!toastEl) return;
  if (!toastEl.parentNode && document.body) document.body.appendChild(toastEl);
  const t = document.createElement("div");
  t.className = "toast" + (kind === "in" ? " in" : "");
  t.innerHTML = `<div class="tci">${kind==="in"?I.down:I.check}</div><div class="tcb">${html}</div>`;
  toastEl.appendChild(t);
  setTimeout(() => { t.classList.add("out"); setTimeout(() => t.remove(), 320); }, 5200);
}

let idleTimer = null, idleBound = false;
function armIdleLock(){
  if (idleTimer){ clearTimeout(idleTimer); idleTimer = null; }
  const mins = getAutoLock();
  if (mins <= 0) return;                 // off
  if (!IS_TAURI) return;                 // don't lock the browser design preview
  if (typeof document !== "undefined" && document.body && document.body.dataset.locked === "1") return;
  idleTimer = setTimeout(() => { if (current !== undefined) lockApp(); }, mins * 60 * 1000);
}
function bindIdleReset(){
  if (idleBound) return; idleBound = true;
  ["mousemove","keydown","mousedown","wheel","touchstart"].forEach(ev =>
    window.addEventListener(ev, () => armIdleLock(), { passive: true }));
}
const hps = n => { n = Number(n||0); return n>=1e6 ? (n/1e6).toFixed(2)+" M" : n>=1e3 ? (n/1e3).toFixed(1)+" k" : Math.round(n).toString(); };
// Human duration from seconds: "~27 min", "~3.2 h", "~2.1 days", "—".
const dur = s => { s = Number(s||0); if (!(s>0)) return "—"; if (s<90) return "~"+Math.round(s)+" s"; if (s<5400) return "~"+Math.round(s/60)+" min"; if (s<172800) return "~"+(s/3600).toFixed(1)+" h"; return "~"+(s/86400).toFixed(1)+" days"; };
// Honest one-line network state derived from the live node.
function syncLabel(){
  if (!S.connected) return { txt: "node offline", cls: "" };
  if (S.status === "synced" || S.tip != null && S.target != null && S.tip >= S.target)
    return { txt: "synced", cls: "g" };
  if (S.tip != null && S.target) {
    const pct = Math.min(99, Math.floor(S.tip / S.target * 100));
    return { txt: `syncing · ${pct}%`, cls: "" };
  }
  return { txt: S.status || "connecting", cls: "" };
}

// ── Privacy Health score ───────────────────────────────────────────
// One honest score from the privacy factors the user controls + the chain
// gives. Pre-fork the shielded component is "locked" and excluded (no unfair
// penalty for a pool that isn't live yet). No fabricated inputs.
function privacyScore(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const comps = [];
  comps.push({ name:"Ghost mode (auto-churn)", score: S.churnOn?100:0, weight: forkLive?20:34,
    status: S.churnOn?"active":"off", action: S.churnOn?null:{label:"Turn on", act:"churn"} });
  const ring = S.ringSize||0;
  comps.push({ name:"Ring cover", score: ring?Math.min(100,Math.round(ring/16*100)):0, weight: forkLive?20:33,
    status: ring?`ring size ${ring}`:"—", chain:true });
  const an = S.anonSet||0;
  comps.push({ name:"Anonymity set", score: an?Math.min(100,Math.round(an/1000*100)):0, weight: forkLive?20:33,
    status: an?num(an)+" outputs":"—", chain:true });
  if (forkLive){
    const cov = S.total>0 ? Math.round(S.shielded/S.total*100) : 0;
    comps.push({ name:"Shielded coverage", score: cov, weight:40,
      status: S.total>0?`${cov}% shielded`:"no balance", action: cov<100?{label:"Shield", act:"shield"}:null });
  } else {
    comps.push({ name:"Shielded coverage", score:null, weight:0, locked:true,
      status:`unlocks h${FORK.toLocaleString()}` });
  }
  let n=0, d=0; comps.forEach(c=>{ if(c.score!=null){ n+=c.score*c.weight; d+=c.weight; } });
  const score = d ? Math.round(n/d) : 0;
  const label = score>=90?"Strong":score>=70?"Good":score>=40?"Fair":"Needs work";
  const color = score>=90?"var(--green)":score>=70?"var(--gold)":score>=40?"var(--amber)":"var(--red)";
  return { score, label, color, comps, forkLive };
}
function privacyHealthPanel(){
  const h = privacyScore();
  const rows = h.comps.map(c=>{
    const right = c.locked
      ? `<span style="color:var(--text-tertiary)">${c.status}</span>`
      : `<span>${c.status}</span>${c.chain?` <span style="color:var(--text-tertiary);font-size:11px">· auto</span>`:""}${c.action?` <button class="seg" data-pha="${c.action.act}">${c.action.label}</button>`:""}`;
    return `<div class="kv"><span class="k">${c.name}</span><span class="v" style="display:flex;gap:8px;align-items:center;justify-content:flex-end">${right}</span></div>`;
  }).join("");
  return `
    <div class="panel">
      <div class="plabel">Privacy Health</div>
      <div style="display:flex;align-items:center;gap:16px;margin:4px 0 12px">
        <div style="font-family:var(--mono);font-size:34px;font-weight:700;color:${h.color};line-height:1">${h.score}</div>
        <div><div style="font-size:13px;color:${h.color};font-weight:600">${h.label}</div><div class="note">out of 100${!h.forkLive?` · shielded unlocks h${FORK.toLocaleString()}`:""}</div></div>
      </div>
      <div style="height:6px;border-radius:999px;background:rgba(255,255,255,.07);overflow:hidden;margin-bottom:12px"><i style="display:block;height:100%;width:${h.score}%;background:${h.color};transition:width .4s ease"></i></div>
      ${rows}
    </div>`;
}

// ── Vault ──────────────────────────────────────────────────────────
function vault(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const toFork = S.tip == null ? null : Math.max(0, FORK - S.tip);
  const sl = syncLabel();
  const cov = S.total > 0 ? Math.round(S.shielded / S.total * 100) : 0;
  const scanning = S.connected && !S.scanned;

  // Pre-fork there is no shielded pool yet: say so honestly instead of a shield nudge.
  const nudge = !forkLive
    ? `<div class="nudge"><div class="ni">${I.clock}</div>
         <div class="nt">Your balance is already <b>ring-private</b> — ring signatures (size ${S.ringSize||16}) + stealth addresses hide sender, recipient &amp; amount on every transaction; privacy is mandatory, there is no transparent mode. The <b>Spark pool</b> at h${FORK.toLocaleString()}${toFork!=null?` (~${num(toFork)} blocks away)`:""} adds an even larger shared anonymity set.</div></div>`
    : (S.transparent > 0
        ? `<div class="nudge"><div class="ni">${I.shieldPlain}</div>
             <div class="nt"><b class="amt">${f(S.transparent)} ${S.unit}</b> is in your ring-private base layer — Shield it into the Spark pool for the largest anonymity set${S.anonSet!=null?` (${num(S.anonSet)} outputs)`:""}.</div></div>`
        : "");

  const activity = `<div class="at-empty" style="padding:28px 8px">${I.clock}
      <p>${scanning ? "Scanning the chain for your transactions…"
          : S.utxoCount > 0 ? "Transaction history isn't wired yet — your balance above is live from the node."
          : "No transactions yet. Sends and receives will appear here once your wallet records them."}</p></div>`;

  return `
    <div class="top">
      <div class="crumb">CyncHub / <b>Vault</b> / Overview</div>
      <div class="top-right">
        <span class="mockbadge ${sl.cls}">● ${sl.txt}</span>
        <span class="pill" id="eye">${I.eye}<span id="eyetxt">Reveal balances</span></span>
      </div>
    </div>
    ${nudge}
    <section class="grid2">
      <div class="panel">
        <div class="hlabel">Total balance${scanning?" · scanning…":""}</div>
        <div class="bigbal"><span class="amt">${f(S.total)}</span><span class="u">${S.unit}</span></div>
        <div class="splits">
          <div class="split"><span class="sk">${I.circle} Ring-private</span><div class="sv amt">${f(S.transparent)}</div></div>
          <div class="split shield"><span class="sk">${I.lock} Shielded</span><div class="sv amt">${f(S.shielded)}</div></div>
        </div>
        <div class="meter"><div class="ml"><span>Spark pool coverage${forkLive?"":" · pre-fork"}</span><b>${cov}% shielded</b></div><div class="bar"><i style="width:${cov}%"></i></div></div>
        <div class="note" style="margin-top:7px">All funds are already <b style="color:var(--gold-200)">ring-private</b> (ring-${S.ringSize||16} + stealth). Spark adds a larger shared pool.</div>
      </div>
      ${privacyHealthPanel()}
    </section>
    <section class="qa">
      <div class="qcard primary" data-screen="send"><div class="qi">${I.up}</div><div class="ql">Send</div><div class="qs">Private by default · hides amount &amp; recipient</div></div>
      <div class="qcard" data-screen="receive"><div class="qi">${I.down}</div><div class="ql">Receive</div><div class="qs">Address + QR · unlinkable subaddresses</div></div>
      <div class="qcard" data-screen="attest"><div class="qi">${I.shield}</div><div class="ql">Attest</div><div class="qs">Prove balance · export a scoped view key</div></div>
      <div class="qcard" data-screen="shield"><div class="qi">${I.shieldPlain}</div><div class="ql">Shield</div><div class="qs">${forkLive?"Join the anonymity set · shield / unshield":"Unlocks at h"+FORK.toLocaleString()}</div></div>
    </section>
    <section class="grid2">
      <div class="panel">
        <div class="plabel">Balances by pool</div>
        <div class="kv"><span class="k">${I.circle}Ring-private · spendable now</span><span class="v amt">${f(S.transparent)}</span></div>
        <div class="kv"><span class="k">${I.lock}Shielded · private</span><span class="v gold amt">${f(S.shielded)}</span></div>
        <div class="kv"><span class="k">${I.clock}Pending · unconfirmed</span><span class="v amt">${f(S.pending)}</span></div>
        <div class="kv"><span class="k">Total</span><span class="v amt">${f(S.total)} ${S.unit}</span></div>
      </div>
      <div class="panel"><div class="plabel" style="display:flex;justify-content:space-between;align-items:center">Activity<a id="vExport" style="color:var(--gold);cursor:pointer;font-size:10.5px;text-transform:none;letter-spacing:0">Export CSV</a></div><div id="vAct">${activity}</div></div>
    </section>
    <p class="note" style="margin-top:4px">Balances blurred by default · non-custodial, keys on device · live from your node · testnet.</p>
  `;
}
function wireVault(){
  const eye = $("#eye");
  if (eye) eye.onclick = () => {
    document.body.classList.toggle("reveal");
    $("#eyetxt").textContent = document.body.classList.contains("reveal") ? "Hide balances" : "Reveal balances";
  };
  const ex = $("#vExport"); if (ex) ex.onclick = exportHistoryCsv;
  // Privacy Health one-tap fixes
  view.querySelectorAll("[data-pha]").forEach(b => b.onclick = async (e) => {
    e.stopPropagation();
    const act = b.dataset.pha;
    if (act === "shield"){ render("shield"); return; }
    if (act === "churn"){
      b.disabled = true; b.textContent = "…";
      try { const st = await invoke("start_churn"); S.churnOn = !!(st && st.running); }
      catch(err){ b.disabled = false; b.textContent = "Turn on"; return; }
      render("vault");
    }
  });
  // Unified Activity preview (top 8); "View all" opens the full history overlay.
  (async () => {
    const el = $("#vAct"); if (!el) return;
    const items = await loadHistoryItems();
    if (!items.length){
      el.innerHTML = `<div class="at-empty" style="padding:28px 8px">${I.clock}<p>No activity yet. Your sends and received payments appear here.</p></div>`;
      return;
    }
    el.innerHTML = items.slice(0, 8).map(histRow).join("")
      + (items.length > 8 ? `<a class="hist-vall" id="vAll">View all ${items.length} transactions →</a>` : "");
    const va = $("#vAll"); if (va) va.onclick = openHistory;
  })();
}

// ── Transaction history (shared model + full overlay) ──────────────
async function loadHistoryItems(){
  let recv = [];
  if (IS_TAURI){ try { recv = (await invoke("list_received")) || []; } catch(e){} }
  const sent = getSentLog();
  const items = [
    ...sent.map(s => ({ kind:"sent", amount:s.amount, height:s.height||0,
      sub:`to ${(s.address||"").slice(0,14)}…${s.memo?` · "${s.memo}"`:""} · ${new Date(s.ts).toLocaleDateString()}` })),
    ...recv.map(r => ({ kind:"recv", amount:r.amount, height:r.height||0, spent:r.spent,
      sub:`block ${Number(r.height).toLocaleString()} · ${r.txOut}` })),
  ];
  items.sort((a,b) => (b.height||0) - (a.height||0));
  return items;
}
function histRow(it){
  return `
    <div class="act">
      <div class="ai ${it.kind==="recv"?"in":""}">${it.kind==="recv"?I.down:I.up}</div>
      <div><div class="al">${it.kind==="recv"?"Received":"Sent"}${it.spent?` <span class="atag">spent</span>`:""}</div><div class="am">${it.sub}</div></div>
      <div><div class="av ${it.kind==="recv"?"in":""}"><span class="amt">${it.kind==="recv"?"+":"−"}${Number(it.amount).toFixed(6)}</span></div><div class="at">${it.kind==="recv"?(it.spent?"spent":"confirmed"):"sent"}</div></div>
    </div>`;
}
let histFilter = "all";
async function openHistory(){
  let ov = document.getElementById("histOv");
  if (!ov){
    ov = document.createElement("div"); ov.id = "histOv"; ov.className = "hist-ov"; ov.tabIndex = -1;
    ov.onkeydown = (e) => { if (e.key === "Escape") ov.style.display = "none"; };
    document.body.appendChild(ov);
  }
  ov.style.display = "grid";
  ov.innerHTML = `<div class="hist-card"><div class="at-empty" style="padding:30px 8px">${I.clock}<p>Reading your transaction history…</p></div></div>`;
  ov.focus();
  const items = await loadHistoryItems();
  renderHistory(ov, items);
}
function renderHistory(ov, items){
  const recvN = items.filter(i => i.kind === "recv").length;
  const sentN = items.filter(i => i.kind === "sent").length;
  const filt = histFilter === "all" ? items : items.filter(i => i.kind === (histFilter === "sent" ? "sent" : "recv"));
  const list = filt.length ? filt.map(histRow).join("")
    : `<div class="at-empty" style="padding:30px 8px">${I.clock}<p>No ${histFilter === "all" ? "" : histFilter + " "}transactions yet.</p></div>`;
  const chips = [["all","All",items.length],["recv","Received",recvN],["sent","Sent",sentN]]
    .map(([k,l,n]) => `<button class="seg ${histFilter===k?'on':''}" data-hf="${k}">${l} · ${n}</button>`).join("");
  ov.innerHTML = `
    <div class="hist-card">
      <div class="hist-head"><div class="h1">Transaction history</div><button class="seg" id="histClose">Close</button></div>
      <div class="hist-filters">${chips}<a id="histCsv" style="margin-left:auto;color:var(--gold);cursor:pointer;font-size:12px">Export CSV</a></div>
      <div class="hist-list">${list}</div>
      <p class="note">Received outputs are read live from your wallet (every incoming output, spent or not). Sent entries are transfers made in CyncHub — CoinCync's mandatory privacy means there is no global "sent" list on-chain to reconstruct.</p>
    </div>`;
  ov.querySelector("#histClose").onclick = () => { ov.style.display = "none"; };
  ov.querySelectorAll("[data-hf]").forEach(b => b.onclick = () => { histFilter = b.dataset.hf; renderHistory(ov, items); });
  const csv = ov.querySelector("#histCsv"); if (csv) csv.onclick = exportHistoryCsv;
  ov.onclick = (e) => { if (e.target === ov) ov.style.display = "none"; };
}

// ── Send ───────────────────────────────────────────────────────────
function showOut(el, kind, html){
  if (!el) return;
  el.style.display = "block"; el.innerHTML = html;
  el.style.color = kind==="err" ? "var(--red)" : kind==="ok" ? "var(--green)" : "var(--text-secondary)";
}
let sendFee = 1; // 1 = normal, 2 = priority (fee multiplier)
function send(){
  const forkLive = S.tip != null && S.tip >= FORK;
  return `
    <div class="pageh"><div class="h1">Send</div><div class="sub">Private by default — ring signatures + stealth addresses hide sender, recipient &amp; amount${forkLive?"":" · Spark shielding unlocks at h"+FORK.toLocaleString()}</div></div>
    <div class="panel" style="max-width:640px">
      <div class="plabel">Transfer</div>
      <div class="at-field"><div class="fl" style="display:flex;justify-content:space-between;align-items:center"><span>Recipient address</span><a id="sPaste" style="color:var(--gold);cursor:pointer;font-size:11px;text-transform:none;letter-spacing:0">Paste</a></div><input class="at-input" id="sAddr" placeholder="tCYNC… · address or coincync: request"><div class="note" id="sAddrInfo" style="margin-top:6px;display:none"></div></div>
      <div id="sContacts" style="margin:-4px 0 12px"></div>
      <div class="at-field"><div class="fl" style="display:flex;justify-content:space-between;align-items:center"><span>Amount (${S.unit})</span><a id="sMax" style="color:var(--gold);cursor:pointer;font-size:11px;text-transform:none;letter-spacing:0">Max</a></div><input class="at-input" id="sAmt" inputmode="decimal" placeholder="0.00"></div>
      <div class="at-field"><div class="fl">Memo — optional, encrypted to the recipient</div><input class="at-input" id="sMemo" placeholder="note…"></div>
      <div class="kv"><span class="k">Spendable</span><span class="v amt">${f(S.transparent)} ${S.unit}</span></div>
      <div class="kv"><span class="k">Fee / priority</span><span class="v" style="display:flex;gap:6px">
        <button class="seg ${sendFee===1?'on':''}" data-fee="1">Normal</button>
        <button class="seg ${sendFee===2?'on':''}" data-fee="2">Priority</button></span></div>
      <div class="note" style="margin-top:6px">Priority raises the fee multiplier so your transaction is picked up sooner. The exact fee is computed from the transaction's size when it's built — CyncHub never shows an estimated number.</div>
      <button class="cta" id="sSend" style="width:100%;margin-top:10px">Review &amp; send</button>
      <div class="note" id="sOut" style="margin-top:12px;display:none"></div>
    </div>
    <p class="note" style="margin-top:16px">Sends are built on device and submitted to your node. Double-check the address — transfers are irreversible.</p>
  `;
}
function renderSendContacts(){
  const el = $("#sContacts"); if (!el) return;
  const cs = getContacts();
  const chips = cs.map(c => `<button class="seg" data-fillc="${c.address}" title="${c.address}">${c.label}<span data-rmc="${c.address}" style="margin-left:6px;opacity:.55">×</span></button>`).join("");
  el.innerHTML = `
    ${cs.length ? `<div class="note" style="margin:2px 0 6px">Saved contacts</div><div style="display:flex;gap:6px;flex-wrap:wrap;margin-bottom:9px">${chips}</div>` : ""}
    <div style="display:flex;gap:6px;align-items:center"><input class="at-input" id="sCLabel" placeholder="name this address" style="max-width:150px;padding:7px 11px"><button class="seg" id="sCSave">Save to contacts</button></div>`;
  el.querySelectorAll("[data-fillc]").forEach(b => b.onclick = (e) => {
    if (e.target && e.target.dataset && e.target.dataset.rmc){ removeContact(e.target.dataset.rmc); renderSendContacts(); return; }
    const a = $("#sAddr"); if (a) a.value = b.dataset.fillc;
  });
  const save = $("#sCSave");
  if (save) save.onclick = () => {
    const addr = ($("#sAddr").value || "").trim();
    if (!addr){ return; }
    const label = ($("#sCLabel").value || "").trim() || (addr.slice(0, 9) + "…");
    addContact(label, addr); const l = $("#sCLabel"); if (l) l.value = ""; renderSendContacts();
  };
}
// CyncHub payment-request URI: coincync:<address>?amount=<x>&memo=<y>.
// A CyncHub convention (CoinCync has no on-chain URI standard) so a request
// made on Receive prefills the sender's Send fields.
function parsePayReq(text){
  if (!/^coincync:/i.test(text||"")) return null;
  try{
    const rest = text.slice(text.indexOf(":")+1);
    const qi = rest.indexOf("?");
    const addr = decodeURIComponent((qi<0?rest:rest.slice(0,qi)).trim());
    const out = { address: addr };
    if (qi>=0) rest.slice(qi+1).split("&").forEach(kv=>{ const i=kv.indexOf("="); if(i<0) return;
      const k=kv.slice(0,i), v=decodeURIComponent(kv.slice(i+1)); if(k==="amount") out.amount=v; if(k==="memo") out.memo=v; });
    return addr ? out : null;
  }catch{ return null; }
}
function applyToSend(text){
  const t = (text||"").trim(); if (!t) return;
  const req = parsePayReq(t), a = $("#sAddr");
  if (req){
    if (a) a.value = req.address;
    if (req.amount){ const am=$("#sAmt"); if(am) am.value=req.amount; }
    if (req.memo){ const mm=$("#sMemo"); if(mm) mm.value=req.memo; }
  } else if (a){ a.value = t; }
  if (a) a.dispatchEvent(new Event("input"));
}
function wireSend(){
  renderSendContacts();
  const paste = $("#sPaste");
  if (paste) paste.onclick = async () => {
    try { const t = await navigator.clipboard.readText(); applyToSend(t); }
    catch(e){ showOut($("#sOut"),"err","Couldn't read the clipboard — paste directly into the field instead."); }
  };
  const btn = $("#sSend"), out = $("#sOut");
  if (!btn) return;
  btn.onclick = () => {
    const addr = ($("#sAddr").value || "").trim();
    const amt = parseFloat($("#sAmt").value || "0");
    const memo = ($("#sMemo").value || "").trim();
    if (!addr){ showOut(out,"err","Enter a recipient address."); return; }
    if (!(amt > 0)){ showOut(out,"err","Enter a positive amount."); return; }
    // A mandatory review step runs the money-protection checks (node sync,
    // spendable, network, live address re-validation, risk flags) before
    // anything is submitted. Nothing is sent until the user confirms there.
    openSendReview({ addr, amt, memo, fee: sendFee });
  };
  // Max — fill spendable (the node computes the fee; reduce slightly if it's tight)
  const maxEl = $("#sMax"); if (maxEl) maxEl.onclick = () => { const a = $("#sAmt"); if (a){ a.value = (S.transparent||0) > 0 ? String(S.transparent) : "0"; a.dispatchEvent(new Event("input")); } };
  // Fee / priority toggle
  view.querySelectorAll("[data-fee]").forEach(b => b.onclick = () => { sendFee = parseInt(b.dataset.fee,10)===2?2:1; view.querySelectorAll("[data-fee]").forEach(x=>x.classList.toggle("on", x===b)); });
  // Live recipient-address validation (debounced)
  const addrEl = $("#sAddr"), info = $("#sAddrInfo");
  // Expand a pasted/typed coincync: request URI into the address + amount + memo
  // (runs before the validation listener below, so validation sees the address).
  if (addrEl) addrEl.addEventListener("input", () => {
    const raw = (addrEl.value||"").trim();
    if (!/^coincync:/i.test(raw)) return;
    const req = parsePayReq(raw);
    if (req && req.address !== raw){
      addrEl.value = req.address;
      if (req.amount){ const am=$("#sAmt"); if(am && !am.value) am.value=req.amount; }
      if (req.memo){ const mm=$("#sMemo"); if(mm && !mm.value) mm.value=req.memo; }
    }
  });
  let vTimer = null;
  const showAddrInfo = (ok, html) => { if (!info) return; info.style.display="block"; info.style.color = ok?"var(--green)":"var(--red)"; info.innerHTML = html; };
  if (addrEl) addrEl.addEventListener("input", () => {
    const v = (addrEl.value||"").trim();
    if (info) info.style.display = "none";
    if (vTimer) clearTimeout(vTimer);
    if (v.length < 8) return;
    vTimer = setTimeout(async () => {
      if (!IS_TAURI){ showAddrInfo(v.startsWith("tCYNC")||v.startsWith("CYNC"), v.startsWith("tCYNC")?"✓ valid · testnet":"✕ not a CoinCync address"); return; }
      try {
        const r = await invoke("validate_address", { address: v });
        if (!r || !r.valid){ showAddrInfo(false, "✕ not a valid CoinCync address"); return; }
        const netOk = !S.network || !r.network || r.network === S.network;
        showAddrInfo(netOk, `${netOk?"✓":"⚠"} ${r.kind||"address"} · ${r.network||"?"}${r.paymentId?" · has payment ID":""}${netOk?"":" — wrong network!"}`);
      } catch(e){ showAddrInfo(false, "✕ not a valid CoinCync address"); }
    }, 400);
  });
}

// ── Send protections: mandatory pre-send review ────────────────────
// Optional per-transaction cap (user-set, in Settings). 0 = no cap.
function getSendCap(){ try { return parseFloat(localStorage.getItem("cynchub.sendCap") || "0") || 0; } catch { return 0; } }
function setSendCap(v){ try { localStorage.setItem("cynchub.sendCap", String(v || 0)); } catch {} }
// Copy a secret, then wipe the clipboard after `secs` if it's still that secret
// (a copied seed lingering in the clipboard is a real theft vector).
async function copyThenClear(text, secs){
  try { await navigator.clipboard.writeText(text); } catch { return false; }
  setTimeout(async () => {
    try { const cur = await navigator.clipboard.readText(); if (cur === text) await navigator.clipboard.writeText(""); } catch {}
  }, (secs || 45) * 1000);
  return true;
}

async function openSendReview(d){
  // d = { addr, amt, memo, fee }. Builds the review overlay, runs every
  // money-protection check, and only enables Confirm when none hard-block.
  let ov = document.getElementById("sendOv");
  if (!ov){
    ov = document.createElement("div"); ov.id = "sendOv"; ov.className = "hist-ov"; ov.tabIndex = -1;
    ov.onkeydown = (e) => { if (e.key === "Escape") ov.style.display = "none"; };
    document.body.appendChild(ov);
  }
  ov.style.display = "grid";
  ov.innerHTML = `<div class="hist-card"><div class="at-empty" style="padding:30px 8px">${I.clock}<p>Running pre-send safety checks…</p></div></div>`;
  ov.focus();

  const blocks = [], warns = [];
  // 1) node must be reachable (offline = can't trust state); synced is a warning.
  const connected = !!S.connected;
  const synced = connected && (S.status === "synced" || (S.node && S.node.isSynced) || (S.tip != null && S.target != null && S.target > 0 && S.tip >= S.target));
  if (!connected) blocks.push("Your node is offline — connect it before sending.");
  else if (!synced) warns.push("Your node may not be fully synced; the transaction could be built against a stale view of the chain.");

  // 2) amount sanity
  if (d.amt > S.transparent + 1e-9) blocks.push(`Amount exceeds your spendable balance of ${f(S.transparent)} ${S.unit}.`);
  const cap = getSendCap();
  if (cap > 0 && d.amt > cap + 1e-9) blocks.push(`Amount is over your per-transaction cap of ${f(cap)} ${S.unit} (change it in Settings → Security).`);

  // 3) anti-swap: re-validate the recipient RIGHT NOW (clipboard-hijack defense)
  let kind = "address", net = S.network, addrOk = true;
  if (IS_TAURI){
    try {
      const r = await invoke("validate_address", { address: d.addr });
      if (!r || !r.valid){ addrOk = false; blocks.push("The recipient address is not a valid CoinCync address."); }
      else {
        kind = r.kind || "address"; net = r.network || net;
        if (S.network && r.network && r.network !== S.network){ addrOk = false; blocks.push(`Wrong network — that is a ${r.network} address but you are on ${S.network}.`); }
      }
    } catch(e){ addrOk = false; blocks.push("Couldn't verify the recipient address — not sending."); }
  }

  // 4) risk flags (allowed, but surfaced)
  const known = getContacts().some(c => (c.address || "") === d.addr);
  if (!known) warns.push("First time sending to this address — check it character-by-character against your source.");
  if (S.transparent > 0 && d.amt > S.transparent * 0.5) warns.push(`This is ${Math.round(d.amt / S.transparent * 100)}% of your spendable balance.`);

  // 2FA gate — opt-in, and only for a LARGE send (over half of spendable, or
  // when spendable is unknown). Small sends stay frictionless.
  let needTotp = false, totpSecret = null;
  const isLarge = !(S.transparent > 0) || d.amt > S.transparent * 0.5;
  try { const st = await invoke("totp_status"); if (st && st.enabled && isLarge){ needTotp = true; totpSecret = await invoke("totp_get"); } } catch {}

  const remaining = Math.max(0, S.transparent - d.amt);
  const canSend = blocks.length === 0;
  const row = (k, v) => `<div class="kv"><span class="k">${k}</span><span class="v">${v}</span></div>`;
  const blockHtml = blocks.map(b => `<div class="note" style="color:var(--red);margin:4px 0">⛔ ${b}</div>`).join("");
  const warnHtml = warns.map(w => `<div class="note" style="color:var(--amber);margin:4px 0">⚠ ${w}</div>`).join("");

  ov.innerHTML = `
    <div class="hist-card">
      <div class="hist-head"><div class="h1">Review transaction</div><button class="seg" id="svClose">Cancel</button></div>
      ${row("Amount", `<b class="amt">${d.amt} ${S.unit}</b>`)}
      ${row("To", `<span class="mono" style="font-size:11px;word-break:break-all">${d.addr}</span>`)}
      ${row("Recipient", `${addrOk ? kind : "unverified"}${net ? " · " + net : ""}`)}
      ${d.memo ? row("Memo", `"${d.memo}"`) : ""}
      ${row("Fee", d.fee === 2 ? "Priority" : "Normal")}
      ${row("Spendable now", `${f(S.transparent)} ${S.unit}`)}
      ${row("Balance after", `~${f(remaining)} ${S.unit} <span class="note" style="display:inline;color:var(--text-tertiary)">(before fee)</span>`)}
      ${(blocks.length || warns.length) ? `<div style="margin-top:10px">${blockHtml}${warnHtml}</div>` : ""}
      ${needTotp ? `<div class="at-field" style="margin-top:12px"><div class="fl">2FA code — required for a large send</div><input class="at-input" id="svCode" inputmode="numeric" maxlength="6" placeholder="6-digit authenticator code" autocomplete="one-time-code"></div>` : ""}
      <button class="cta" id="svConfirm" style="width:100%;margin-top:12px" ${canSend ? "" : "disabled"}>${canSend ? `Confirm — send ${d.amt} ${S.unit}` : "Resolve the blockers above to send"}</button>
      <div class="note" id="svOut" style="margin-top:10px;display:none"></div>
      <p class="note" style="margin-top:10px">Transfers are private and <b>irreversible</b> — once submitted they can't be recalled. The recipient address is re-checked here to catch clipboard tampering.</p>
    </div>`;
  ov.querySelector("#svClose").onclick = () => { ov.style.display = "none"; };
  ov.onclick = (e) => { if (e.target === ov) ov.style.display = "none"; };
  const conf = ov.querySelector("#svConfirm");
  if (conf && canSend) conf.onclick = async () => {
    const svOut = ov.querySelector("#svOut");
    // Large-send 2FA check before anything is submitted.
    if (needTotp){
      const code = (ov.querySelector("#svCode") && ov.querySelector("#svCode").value || "").trim();
      if (!totpSecret || !(await totpVerify(totpSecret, code))){
        if (svOut){ svOut.style.display = "block"; svOut.style.color = "var(--red)"; svOut.textContent = "Enter a valid 2FA code to confirm this large send."; }
        return;
      }
    }
    conf.disabled = true; conf.textContent = "Sending…";
    try {
      const txid = await invoke("send_transaction", { address: d.addr, amount: d.amt, memo: d.memo || null, feeMultiplier: d.fee });
      recordSend({ txid, address: d.addr, amount: d.amt, memo: d.memo, ts: Date.now(), height: S.tip || 0 });
      ov.style.display = "none";
      showOut($("#sOut"), "ok", `Sent ✓ — <span class="mono" style="font-size:11px;word-break:break-all">${txid}</span>`);
      ["sAddr","sAmt","sMemo"].forEach(id => { const el = $("#" + id); if (el) el.value = ""; });
      pollWallet();
    } catch(e){
      const msg = String((e && e.message) || e);
      if (svOut){
        svOut.style.display = "block"; svOut.style.color = "var(--red)"; svOut.textContent = msg;
        const low = msg.toLowerCase();
        if (low.includes("auto-churn") || low.includes("too large") || low.includes("max_safe") || low.includes("redistribute")){
          svOut.innerHTML += `<div style="margin-top:8px;color:var(--text-secondary)">This amount is larger than any single output can cover. Turn on <b>Ghost mode</b> in Privacy Center to redistribute (auto-churn) your outputs, then try again.</div>`;
        }
      }
      conf.disabled = false; conf.textContent = `Confirm — send ${d.amt} ${S.unit}`;
    }
  };
}

// ── Receive (privacy-first) ────────────────────────────────────────
let rKind = "main"; // main | private | integrated
function rKindLabel(){
  return rKind === "private" ? `· fresh · <span style="color:var(--green)">unlinkable</span>`
       : rKind === "integrated" ? `· integrated (payment ID)`
       : `· main`;
}
function receive(){
  return `
    <div class="pageh"><div class="h1">Receive</div><div class="sub">Privacy by default — every address here is fresh and unlinkable</div></div>
    <div class="nudge" style="margin-bottom:16px"><div class="ni">${I.shield}</div>
      <div class="nt"><b>CyncHub hands you a fresh private address automatically.</b> CoinCync subaddresses are unlinkable — two senders can't tell they paid the same wallet, and outsiders can't tie your payments together. Tap <b>New private address</b> for the next sender; every payment also lands at a one-time stealth address on-chain.</div></div>
    <section class="grid2">
      <div class="panel" style="text-align:center">
        <div class="plabel" style="text-align:left">Receiving address <span id="rKind" style="color:var(--gold-200);font-weight:400;text-transform:none;letter-spacing:0">${rKindLabel()}</span></div>
        <div id="rQr" style="display:flex;justify-content:center;align-items:center;min-height:160px;padding:14px 0;color:var(--text-tertiary)">generating…</div>
        <div id="rAddr" class="mono" style="font-size:11px;word-break:break-all;color:var(--text-secondary);margin:6px 4px 14px">loading…</div>
        <div class="at-actions" style="justify-content:center"><button class="cta" id="rNew">New private address</button><button class="ghost" id="rCopy">Copy</button></div>
      </div>
      <div class="panel">
        <div class="plabel">Address options</div>
        <p class="note" style="margin-bottom:14px">A <b>fresh private address</b> is best — a new, unlinkable one per sender. An <b>integrated address</b> adds a payment ID so you can match an incoming payment to an invoice. Your <b>main address</b> is fine for a one-off or a public tip jar, but reusing it lets a sender recognize you again.</p>
        <div style="display:flex;gap:10px;flex-wrap:wrap"><button class="ghost" id="rReq">Request a payment</button><button class="ghost" id="rInt">Integrated address</button><button class="ghost" id="rMain">Show main address</button></div>
        <div id="rReqBox" style="margin-top:14px;display:none"></div>
        <div class="note" id="rMore" style="margin-top:16px;display:none"></div>
      </div>
    </section>
  `;
}
async function setReceiveAddr(addr, kind){
  if (addr) S.address = addr;
  if (kind) rKind = kind;
  const a = $("#rAddr"); if (a) a.textContent = addr || "—";
  const k = $("#rKind"); if (k) k.innerHTML = rKindLabel();
  const q = $("#rQr");
  if (q && addr){
    try { const svg = await invoke("generate_qr_svg", { payload: addr }); q.innerHTML = `<div style="width:180px;height:180px;background:#fff;border-radius:8px;padding:8px;box-sizing:border-box">${svg}</div>`; }
    catch { q.textContent = "(QR unavailable)"; }
  }
}
function wireReceive(){
  (async () => {
    // Privacy by default: automatically hand out a FRESH, unlinkable address.
    // The main address is a deliberate opt-in ("Show main address"), never the
    // default — so a user is private without having to think about it.
    if (IS_TAURI){
      try { const a = await invoke("new_subaddress"); await setReceiveAddr(a, "private"); return; } catch(e){}
    }
    let addr = S.address;
    if (!addr){ try { addr = await invoke("get_wallet_address"); } catch{} }
    if (addr) await setReceiveAddr(addr, "main");
  })();
  const copy = $("#rCopy"); if (copy) copy.onclick = async () => { try{ await navigator.clipboard.writeText(S.address||""); }catch{} copy.textContent="Copied ✓"; setTimeout(()=>copy.textContent="Copy",1400); };
  const errMore = (e) => { const m = $("#rMore"); if (!m) return; m.style.display="block"; m.style.color="var(--red)"; m.textContent = String((e && e.message) || e); };
  const info = (html) => { const m = $("#rMore"); if (!m) return; m.style.display="block"; m.style.color="var(--text-secondary)"; m.innerHTML = html; };
  const neu = $("#rNew"); if (neu) neu.onclick = async () => { neu.disabled=true; neu.textContent="Generating…"; try{ const a = await invoke("new_subaddress"); await setReceiveAddr(a, "private"); info(`Fresh unlinkable address ready — share it with just this one sender.`); }catch(e){ errMore(e); } neu.disabled=false; neu.textContent="New private address"; };
  const int = $("#rInt"); if (int) int.onclick = async () => { int.disabled=true; try{ const a = await invoke("integrated_address"); await setReceiveAddr(a, "integrated"); info(`Integrated address — carries a payment ID so you can match the incoming payment to an invoice.`); }catch(e){ errMore(e); } int.disabled=false; };
  const main = $("#rMain"); if (main) main.onclick = async () => { main.disabled=true; try{ const a = await invoke("get_wallet_address"); await setReceiveAddr(a, "main"); info(`This is your main address. Fine for a one-off, but reusing it lets senders link your payments — prefer a fresh private address.`); }catch(e){ errMore(e); } main.disabled=false; };
  const reqBtn = $("#rReq");
  if (reqBtn) reqBtn.onclick = () => {
    const box = $("#rReqBox"); if (!box) return;
    if (box.style.display === "block"){ box.style.display = "none"; box.innerHTML = ""; return; }
    box.style.display = "block";
    box.innerHTML = `
      <div class="at-field"><div class="fl">Request amount (${S.unit}) — optional</div><input class="at-input" id="rqAmt" inputmode="decimal" placeholder="0.00"></div>
      <div class="at-field"><div class="fl">Note / memo — optional</div><input class="at-input" id="rqMemo" placeholder="what's it for"></div>
      <button class="cta" id="rqMake" style="width:100%">Make request</button>
      <div id="rqOut" style="margin-top:12px;display:none"></div>`;
    const make = $("#rqMake");
    if (make) make.onclick = async () => {
      const addr = S.address || "";
      if (!addr){ info("Generate a receiving address first."); return; }
      const amt = ($("#rqAmt").value||"").trim();
      const memo = ($("#rqMemo").value||"").trim();
      const q = [];
      if (amt && parseFloat(amt) > 0) q.push("amount=" + encodeURIComponent(amt));
      if (memo) q.push("memo=" + encodeURIComponent(memo));
      const uri = "coincync:" + addr + (q.length ? ("?" + q.join("&")) : "");
      const out = $("#rqOut"); if (!out) return;
      out.style.display = "block";
      let qr = "";
      try { qr = await invoke("generate_qr_svg", { payload: uri }); } catch {}
      out.innerHTML = `
        ${qr?`<div style="display:flex;justify-content:center;margin-bottom:10px"><div style="width:150px;height:150px;background:#fff;border-radius:8px;padding:7px;box-sizing:border-box">${qr}</div></div>`:""}
        <div class="mono" style="font-size:11px;word-break:break-all;color:var(--text-secondary);margin-bottom:8px">${uri}</div>
        <button class="seg" id="rqCopy">Copy request</button>
        <p class="note" style="margin-top:10px">${amt&&parseFloat(amt)>0?`Requesting <b>${amt} ${S.unit}</b>. `:""}The payer pastes this into CyncHub's Send to prefill the address${amt?", amount":""}${memo?" and memo":""}. It's a CyncHub convention — other wallets read only the plain address.</p>`;
      const cp = $("#rqCopy");
      if (cp) cp.onclick = async () => { try{ await navigator.clipboard.writeText(uri); }catch{} cp.textContent = "Copied ✓"; setTimeout(()=>cp.textContent = "Copy request", 1400); };
    };
  };
}

// ── Shield / Unshield (Spark pool · activates at h29000) ────────────
let shDir = "shield"; // "shield" (transparent→pool) | "unshield" (pool→transparent)
function shield(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const toFork = S.tip == null ? null : Math.max(0, FORK - S.tip);
  const isShield = shDir === "shield";
  const srcLabel = isShield ? "Ring-private" : "Shielded";
  const srcBal = isShield ? S.transparent : S.shielded;
  const gate = !forkLive
    ? `<div class="nudge" style="margin-bottom:18px"><div class="ni">${I.clock}</div>
         <div class="nt">The shielded pool activates at <b>h${FORK.toLocaleString()}</b>${toFork!=null?` — <b class="amt">~${toFork.toLocaleString()}</b> blocks away`:""}. Shield &amp; unshield unlock then.</div></div>`
    : "";
  return `
    <div class="pageh"><div class="h1">Shield</div><div class="sub">Move value between your ring-private base balance and the Spark shielded pool</div></div>
    ${gate}
    <div class="at-types">
      <button class="at-type ${isShield?"on":""}" data-sh="shield"><div class="tt">${I.shieldPlain} Shield</div><div class="ts">Base → Spark pool · join the largest anonymity set.</div></button>
      <button class="at-type ${!isShield?"on":""}" data-sh="unshield"><div class="tt">${I.unshield} Unshield</div><div class="ts">Pool → base · value-revealing clean exit.</div></button>
    </div>
    <div class="panel" style="max-width:640px;margin-top:16px">
      <div class="plabel">${isShield?"Shield into the Spark pool":"Unshield (value-revealing exit)"}</div>
      <div class="at-field"><div class="fl">Amount (${S.unit})</div><input class="at-input" id="shAmt" inputmode="decimal" placeholder="0.00" ${forkLive?"":"disabled"}></div>
      <div class="kv"><span class="k">${srcLabel} balance</span><span class="v amt">${f(srcBal)} ${S.unit}</span></div>
      ${!isShield?`<div class="kv"><span class="k">Shielded notes</span><span class="v">${S.shieldedNotes||0}</span></div>`:""}
      <button class="cta" id="shGo" style="width:100%;margin-top:10px" ${forkLive?"":"disabled"}>${forkLive?(isShield?"Review &amp; shield":"Review &amp; unshield"):"Unlocks at h"+FORK.toLocaleString()}</button>
      <div class="note" id="shOut" style="margin-top:12px;display:none"></div>
    </div>
    ${!isShield ? cleanExitWizard(forkLive) : ""}
    <p class="note" style="margin-top:16px">Shielding hides amount and ownership inside the Spark anonymity set. Unshielding produces a public, value-revealing output back to this wallet — your clean transparent exit.</p>
  `;
}
// Clean-exit wizard — a guided "delisting-insurance" exit from the shielded pool:
// decorrelate with churn, unshield to transparent, then send to your destination.
function cleanExitWizard(forkLive){
  const step = (n, title, body, extra) => `
    <div style="display:flex;gap:12px;padding:12px 0;border-top:1px solid var(--border)">
      <div style="flex:0 0 24px;height:24px;border-radius:50%;border:1px solid var(--border-strong);display:grid;place-items:center;font-family:var(--mono);font-size:12px;color:var(--gold)">${n}</div>
      <div style="flex:1"><div style="font-weight:600;font-size:13px">${title}</div><div class="note" style="margin-top:3px">${body}</div>${extra||""}</div>
    </div>`;
  const churnBtn = forkLive
    ? `<div style="margin-top:8px"><button class="seg ${S.churnOn?'on':''}" id="ceChurn" ${S.churnOn?'disabled':''}>${S.churnOn?"Ghost mode on":"Turn on ghost mode"}</button></div>`
    : "";
  const sendBtn = forkLive ? `<div style="margin-top:8px"><button class="seg" data-screen="send">Go to Send</button></div>` : "";
  return `
    <div class="panel" style="max-width:640px;margin-top:16px">
      <div class="plabel">Clean-exit wizard ${forkLive?"":"· preview"}</div>
      <p class="note" style="margin-bottom:4px">A clean exit is your <b style="color:var(--gold-200)">delisting insurance</b> — a public, provable trail from the shielded pool to a transparent output an exchange will accept, with your private history left private.</p>
      ${step(1,"Decorrelate","Run ghost-mode churn first so the coins you exit can't be linked back to your shielded activity.",churnBtn)}
      ${step(2,"Unshield","Move the amount above out of the pool — it becomes a transparent, value-revealing output back to your own wallet.","")}
      ${step(3,"Exit","Send the unshielded coins to your exchange or custodian — they can verify the public unshield trail, while the rest of your history stays private.",sendBtn)}
    </div>`;
}
function wireShield(){
  view.querySelectorAll("[data-sh]").forEach(el => el.onclick = () => { shDir = el.dataset.sh; render("shield"); });
  const forkLive = S.tip != null && S.tip >= FORK;
  // clean-exit step 1: one-tap ghost mode (available pre- and post-fork)
  const ce = $("#ceChurn");
  if (ce && !S.churnOn) ce.onclick = async () => {
    ce.disabled = true; ce.textContent = "…";
    try { const st = await invoke("start_churn"); S.churnOn = !!(st && st.running); }
    catch(e){ ce.disabled = false; ce.textContent = "Turn on ghost mode"; return; }
    render("shield");
  };
  if (!forkLive) return;
  const btn = $("#shGo"), out = $("#shOut");
  if (!btn) return;
  const isShield = shDir === "shield";
  let confirming = false;
  btn.onclick = async () => {
    const amt = parseFloat($("#shAmt").value || "0");
    const srcBal = isShield ? S.transparent : S.shielded;
    if (!(amt > 0)){ showOut(out,"err","Enter a positive amount."); return; }
    if (amt > srcBal + 1e-9){ showOut(out,"err",`Amount exceeds your ${isShield?"ring-private":"shielded"} ${f(srcBal)} ${S.unit}.`); return; }
    if (!confirming){ confirming = true; btn.innerHTML = `Confirm — ${isShield?"shield":"unshield"} ${amt} ${S.unit}`; showOut(out,"",`${isShield?"Shielding":"Unshielding"} <b>${amt} ${S.unit}</b>. Click again to confirm.`); return; }
    btn.disabled = true; btn.textContent = isShield?"Shielding…":"Unshielding…";
    try {
      const txid = await invoke(isShield?"shield_funds":"unshield_funds", { amount: amt });
      showOut(out,"ok",`Submitted ✓ — <span class="mono" style="font-size:11px;word-break:break-all">${txid}</span>`);
      $("#shAmt").value = ""; pollWallet();
    } catch(e){ showOut(out,"err", String((e && e.message) || e)); }
    btn.disabled = false; btn.innerHTML = isShield?"Review &amp; shield":"Review &amp; unshield"; confirming = false;
  };
  const amtEl = $("#shAmt"); if (amtEl) amtEl.oninput = () => { if (confirming){ confirming=false; btn.innerHTML = isShield?"Review &amp; shield":"Review &amp; unshield"; if (out) out.style.display="none"; } };
}

// ── Lens ───────────────────────────────────────────────────────────
function lens(){
  const toFork = S.tip == null ? null : Math.max(0, FORK - S.tip);
  const forkLive = S.tip != null && S.tip >= FORK;
  const sl = syncLabel();
  const supplyTxt = S.supply == null ? "—"
    : S.supply >= 1e6 ? (S.supply/1e6).toFixed(2)+" M"
    : Math.round(S.supply).toLocaleString();
  return `
    <div class="pageh"><div class="h1">Lens</div><div class="sub">Network overview · the full explorer lives at its own site</div></div>
    <div class="tiles">
      <div class="tile"><div class="tk">Chain tip</div><div class="tv">${num(S.tip)}</div><div class="td ${sl.cls}">${sl.txt}</div></div>
      <div class="tile"><div class="tk">Peers</div><div class="tv">${num(S.peers)}</div><div class="td">${S.connected?"connected":"—"}</div></div>
      <div class="tile"><div class="tk">Shielded fork</div><div class="tv">h${FORK.toLocaleString()}</div><div class="td">${forkLive?"active":toFork!=null?"~"+toFork.toLocaleString()+" blocks to go":"—"}</div></div>
      <div class="tile"><div class="tk">Anon set</div><div class="tv">${num(S.anonSet)}</div><div class="td">${S.ringSize!=null?"ring size "+S.ringSize:"—"}</div></div>
    </div>
    <div class="panel"><div class="plabel">Supply &amp; network</div>
      <div class="kv"><span class="k">Circulating supply</span><span class="v">${supplyTxt==="—"?"—":supplyTxt+" "+S.unit}</span></div>
      <div class="kv"><span class="k">Network</span><span class="v">${S.network||"—"}</span></div>
      <div class="kv"><span class="k">Target height</span><span class="v">${num(S.target)}</span></div>
      <div class="kv"><span class="k">Audit status</span><span class="v">pre-audit · testnet</span></div>
    </div>
    <p class="note" style="margin-top:16px">Lens shows public chain state from your node — no private wallet data. Open the full explorer in your browser.</p>
  `;
}

// ── Attest (real disclose CLI) ─────────────────────────────────────
let atKind = "balance";
// One-click disclosure presets — prefill the config for common real scenarios.
const YEAR_BLOCKS = Math.round(365*24*3600/120); // ~1 year at 120s blocks
const AT_PRESETS = {
  exchange: { kind:"balance", label:"Exchange proof-of-funds", desc:"Prove you hold ≥ a threshold — amount stays hidden", fill:()=>({ thr:"1000" }) },
  counterparty: { kind:"balance", label:"Counterparty / OTC", desc:"Prove solvency for a deal without revealing your balance", fill:()=>({ thr:"5000" }) },
  auditor: { kind:"viewkey", label:"Auditor — full history", desc:"Read-only view key, genesis → now", fill:()=>({ from:0, to:(S.tip||0) }) },
  taxyear: { kind:"viewkey", label:"Tax year", desc:"Read-only view key for the last ~12 months of blocks", fill:()=>({ from:Math.max(0,(S.tip||0)-YEAR_BLOCKS), to:(S.tip||0) }) },
};
let atFill = { thr:"1000", from:0, to:null };
function attest(){
  const isBal = atKind === "balance";
  const toVal = atFill.to != null ? atFill.to : (S.tip||0);
  const cfg = isBal ? `
    <div class="at-field"><div class="fl">Prove one of your outputs is worth at least (CYNC)</div><input class="at-input" id="atThr" value="${atFill.thr||"1000"}"></div>
    <div class="at-field"><div class="fl">Which output to prove</div>
      <select class="at-input" id="atUtxoSel"><option value="">loading your outputs…</option></select>
      <div class="note" id="atUtxoNote" style="margin-top:7px">A balance proof reveals that one received output is worth at least your threshold — never the exact amount.</div>
    </div>
  ` : `
    <div class="at-field"><div class="fl" style="display:flex;gap:16px"><span style="flex:1">From height</span><span style="flex:1">To height</span></div>
      <div style="display:flex;gap:12px"><input class="at-input" id="atFrom" value="${atFill.from||0}"><input class="at-input" id="atTo" value="${toVal}"></div></div>
  `;
  const presets = Object.entries(AT_PRESETS).map(([k,p])=>
    `<button class="seg" data-atp="${k}" title="${p.desc}">${p.label}</button>`).join("");
  return `
    <div class="pageh"><div class="h1">Attest</div><div class="sub">Selective disclosure · reveal only what you choose</div></div>
    <p class="note" style="max-width:640px;margin-bottom:14px">Your history is private by default. Mint proofs that reveal <b style="color:var(--gold-200)">exactly</b> what you choose — to an exchange, an auditor, a counterparty — and nothing else. Built &amp; signed on this device.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;max-width:640px"><span class="note" style="width:100%;margin-bottom:2px">Quick presets</span>${presets}</div>
    <div class="at-types">
      <button class="at-type ${isBal?"on":""}" data-atk="balance"><div class="tt">${I.shield} Balance proof</div><div class="ts">Prove an output is worth ≥ a threshold without revealing the amount.</div></button>
      <button class="at-type ${!isBal?"on":""}" data-atk="viewkey"><div class="tt">${I.shield} Scoped view key</div><div class="ts">Grant read-only visibility over a bounded block range (e.g. a tax year).</div></button>
    </div>
    <div class="at-work">
      <div class="panel"><div class="plabel">Configure · ${isBal?"Balance proof":"Scoped view key"}</div>${cfg}
        <button class="cta" id="atGen" style="width:100%;margin-top:4px">Generate ${isBal?"proof":"view key"}</button></div>
      <div class="panel"><div class="plabel">Output</div><div class="at-out" id="atOut">
        <div class="at-empty">${I.shield}<p>Configure a disclosure and press <b style="color:var(--text-secondary)">Generate</b>. Built &amp; signed locally — keys never leave this device.</p></div>
      </div></div>
    </div>
  `;
}
// Load the user's unspent outputs into the balance-proof picker, or guide them
// to get funds first if they have none (a balance proof needs a real output).
async function loadAtBalanceOutputs(){
  const sel = document.getElementById("atUtxoSel");
  const note = document.getElementById("atUtxoNote");
  const gen = document.getElementById("atGen");
  if (!sel) return;
  if (!IS_TAURI){ sel.innerHTML = `<option value="0">demo output · 49.0000 ${S.unit}</option>`; return; }
  try {
    const rows = await invoke("list_received");
    const unspent = (rows || []).filter(r => !r.spent);
    if (!unspent.length){
      sel.innerHTML = `<option value="">— no outputs yet —</option>`; sel.disabled = true;
      if (note){ note.innerHTML = `You have no received outputs yet — a balance proof needs at least one. <b style="color:var(--gold-200)">Receive</b> or <b style="color:var(--gold-200)">mine</b> some ${S.unit} first, then come back.`; }
      if (gen){ gen.disabled = true; gen.textContent = "No outputs to prove"; }
      return;
    }
    unspent.sort((a,b) => b.amount - a.amount); // largest first (most likely to clear a threshold)
    sel.disabled = false;
    sel.innerHTML = unspent.map(r => `<option value="${r.idx}">${Number(r.amount).toFixed(4)} ${S.unit} · block ${Number(r.height).toLocaleString()}</option>`).join("");
    if (note){ note.innerHTML = `A balance proof reveals that this output is worth at least your threshold — never the exact amount. Pick one that clears it.`; }
    if (gen){ gen.disabled = false; gen.textContent = "Generate proof"; }
  } catch(e){ /* leave placeholder; generate surfaces a clean error */ }
}
function wireAttest(){
  document.querySelectorAll("[data-atk]").forEach(b => b.onclick = () => { atKind = b.dataset.atk; render("attest"); });
  if (atKind === "balance") loadAtBalanceOutputs();
  // one-click presets: set the disclosure kind + prefill its fields
  document.querySelectorAll("[data-atp]").forEach(b => b.onclick = () => {
    const p = AT_PRESETS[b.dataset.atp]; if (!p) return;
    atKind = p.kind;
    const f = p.fill();
    atFill = { thr: f.thr != null ? f.thr : atFill.thr, from: f.from != null ? f.from : 0, to: f.to != null ? f.to : null };
    render("attest");
  });
  const gen = $("#atGen"), out = $("#atOut");
  if (gen) gen.onclick = async () => {
    gen.disabled = true;
    out.innerHTML = `<div class="at-empty"><p>Building proof &amp; signing on device…</p></div>`;
    let res;
    try {
      if (atKind === "balance") {
        // Tauri v2 exposes Rust snake_case args as camelCase to JS.
        const sel = $("#atUtxoSel");
        const ui = sel && sel.value !== "" ? (parseInt(sel.value, 10) || 0) : 0;
        res = await invoke("disclose_balance", { threshold: ($("#atThr").value || "1000").trim(), utxoIndex: ui });
      } else {
        res = await invoke("disclose_scoped_view_key", {
          fromHeight: parseInt($("#atFrom").value || "0", 10) || 0,
          toHeight: parseInt($("#atTo").value || "0", 10) || 0,
        });
      }
    } catch (e) {
      const msg = (e && (e.message || e.toString())) || "could not generate";
      out.innerHTML = `<div class="note" style="color:var(--red);line-height:1.6"><b>Couldn't generate</b> — ${String(msg)}</div>`;
      gen.disabled = false;
      return;
    }
    const artifact = (res && res.artifact) || "";
    out.innerHTML = `
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:14px">
        <div style="width:32px;height:32px;border-radius:50%;background:rgba(52,227,136,.1);border:1px solid rgba(52,227,136,.4);color:var(--green);display:grid;place-items:center">${I.check}</div>
        <div><div style="font-family:var(--disp);font-size:16px">${atKind==="balance"?"Balance proof minted":"Scoped view key issued"}</div>
        <div style="font-family:var(--mono);font-size:10.5px;color:var(--text-tertiary);margin-top:2px">${atKind==="balance"?"CYNC-ATTEST · range proof":"CYNC-VIEWKEY · bounded"} · signed on device</div></div>
      </div>
      <div class="at-artifact">${artifact}</div>
      <div class="note" style="margin-top:8px">Hand-off: <b style="color:var(--text-secondary)">Copy</b> or <b style="color:var(--text-secondary)">Download</b> and send to your verifier — they import it with the <code>disclose verify-*</code> CLI.</div>
      <div class="at-actions"><button class="cta" id="atCopy">Copy proof</button><button class="ghost" id="atDl">Download</button><button class="ghost" id="atNew">New disclosure</button></div>`;
    gen.disabled = false;
    const copy = $("#atCopy"); if (copy) copy.onclick = async () => { try{ await navigator.clipboard.writeText(artifact);}catch{} copy.textContent="Copied ✓"; setTimeout(()=>copy.textContent="Copy proof",1400); };
    const dl = $("#atDl"); if (dl) dl.onclick = () => {
      try{ const b=new Blob([artifact],{type:"text/plain"});const u=URL.createObjectURL(b);const a=document.createElement("a");a.href=u;a.download=(atKind==="balance"?"cync-balance-proof":"cync-scoped-view-key")+".txt";document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(u),800);dl.textContent="Saved ✓"; }catch{dl.textContent="Use Copy";}
      setTimeout(()=>dl.textContent="Download",1400);
    };
    const neu = $("#atNew"); if (neu) neu.onclick = () => render("attest");
  };
}

// ── Swap / Mining / Nodes / Diagnostics / Settings ─────────────────
function swap(){
  return `
    <div class="pageh"><div class="h1">Swap</div><div class="sub">CYNC ↔ BTC · trustless atomic swaps · CIP-001</div></div>
    <div class="future"><div class="fi">${I.clock}</div><div><div class="ft">Ships post-audit</div>
      <div class="fx">Trustless CYNC↔BTC swaps via the merge-mined CyncHub liquidity layer — the hub never holds your funds. Enabled after the swap layer clears its own audit.</div></div></div>
  `;
}
function recLabel(m){
  if (!m || m.recommend==="measuring") return { t:"Measuring your hashrate…", cls:"" };
  if (m.recommend==="solo") return { t:`Solo is worthwhile — ~a block every ${dur(m.estSoloSecs).replace("~","")}`, cls:"g" };
  return { t:`Solo would take ${dur(m.estSoloSecs)} — a pool earns steadier shares`, cls:"" };
}
// Your share of total network hashrate (difficulty-derived net includes you).
function shareOf(m){ return (m && m.hashrate>0 && m.netHashrate>0) ? Math.min(1, m.hashrate/m.netHashrate) : null; }
function shareTxt(m){ const s = shareOf(m); return s==null ? "—" : (s>=0.1?(s*100).toFixed(0):(s*100).toFixed(1))+"%"; }
// What Auto decided and why — plain language, so the user trusts the routing.
function autoBanner(m, running){
  if (!running) return "";
  if (m.recommend==="measuring") return `<b>Auto</b> is measuring your hashrate to pick the mode where you actually earn…`;
  if (m.mode==="pool") return `<b>Auto → Pool.</b> Solo would take ${dur(m.estSoloSecs)} to find a block, so you're earning steadier shares on the pool instead.`;
  if (m.recommend==="pool"){
    return (S.poolUrl||"").trim()
      ? `<b>Auto.</b> Solo would take ${dur(m.estSoloSecs)} — routing you to the pool for steadier shares…`
      : `<b>Auto → Solo (no pool set).</b> Solo would take ${dur(m.estSoloSecs)} here — add a pool address below and Auto will switch you to steadier shares.`;
  }
  return `<b>Auto → Solo.</b> You're ${shareTxt(m)} of the network, finding ~a block every ${dur(m.estSoloSecs).replace("~","")} — and you keep the whole reward.`;
}
function mining(){
  const m = S.mining;
  const maxT = m.maxThreads || 4;
  const want = Math.min(maxT, S.minerThreads || Math.max(1, maxT - 1));
  const canMine = S.connected;
  const mode = S.minerMode;                 // auto | solo | pool
  const running = m.mining;
  const showPool = mode === "pool" || mode === "auto";
  const poolRunning = running && m.mode === "pool";
  const rec = recLabel(m);
  const routed = (mode==="auto" && running) ? ` · routed to ${m.mode}` : "";
  const third = poolRunning
    ? `<div class="tile"><div class="tk">Shares</div><div class="tv" id="mThird">${m.sharesAccepted||0}</div><div class="td" id="mThirdSub">accepted${m.sharesRejected?` · ${m.sharesRejected} rej`:""}</div></div>`
    : `<div class="tile"><div class="tk">Blocks found</div><div class="tv" id="mThird">${m.blocksFound||0}</div><div class="td" id="mThirdSub">this run</div></div>`;
  return `
    <div class="pageh"><div class="h1">Mining</div><div class="sub">RandomX · solo, pool, or smart auto — everyone gets a share${routed}</div></div>
    <div class="tiles">
      <div class="tile"><div class="tk">Status</div><div class="tv" id="mStatus" style="font-size:20px">${running?"Mining":"Idle"}</div><div class="td ${running?"g":""}" id="mStatusSub">${running?(m.mode==="pool"?"pool":"solo"):"stopped"}</div></div>
      <div class="tile"><div class="tk">Hashrate</div><div class="tv"><span id="mHash">${hps(m.hashrate)}</span> <span style="font-size:13px;color:var(--text-tertiary)">H/s</span></div><div class="td" id="mHashSub">${running?(m.hashrate>0?"live":"warming up…"):"—"}</div></div>
      ${third}
      <div class="tile"><div class="tk">Threads</div><div class="tv" id="mThreadsTv">${running?m.threads:want}</div><div class="td">of ${maxT} cores</div></div>
    </div>
    <div id="mWarm" class="nudge" style="margin-bottom:16px;display:${running && !(m.hashrate>0) ? 'flex':'none'}"><div class="ni">${I.clock}</div>
      <div class="nt"><b>Warming up</b> — building the ~2 GB RandomX dataset (one-time, ~30–60s). The miner is running; your hashrate appears here the moment it's ready.</div></div>
    ${(mode==="auto" && running) ? `<div id="mAuto" class="nudge" style="margin-bottom:16px;border-left-color:var(--gold)"><div class="ni">${I.shield}</div><div class="nt" id="mAutoTxt">${autoBanner(m, running)}</div></div>` : ""}
    <div class="panel"><div class="plabel">Smart mining advisor</div>
      <div class="kv"><span class="k">Your hashrate</span><span class="v"><span id="mHash2">${hps(m.hashrate)}</span> H/s</span></div>
      <div class="kv"><span class="k">Network hashrate</span><span class="v" id="mNet">${m.netHashrate?hps(m.netHashrate)+" H/s":"—"}</span></div>
      <div class="kv"><span class="k">Your share of network</span><span class="v ${shareOf(m)>=0.25?'g':''}" id="mShare">${shareTxt(m)}</span></div>
      <div class="kv"><span class="k">Difficulty</span><span class="v" id="mDiff">${m.difficulty?num(Math.round(m.difficulty)):"—"}</span></div>
      <div class="kv"><span class="k">Expected block (solo)</span><span class="v" id="mEst">${dur(m.estSoloSecs)}</span></div>
      <div class="kv"><span class="k">Recommendation</span><span class="v ${rec.cls}" id="mRec">${rec.t}</span></div>
    </div>
    <div class="panel"><div class="plabel">Rig control</div>
      <div class="kv"><span class="k">Mode</span>
        <span class="v" style="display:flex;gap:6px">
          <button class="seg ${mode==='auto'?'on':''}" data-mm="auto" ${running?'disabled':''}>Auto</button>
          <button class="seg ${mode==='solo'?'on':''}" data-mm="solo" ${running?'disabled':''}>Solo</button>
          <button class="seg ${mode==='pool'?'on':''}" data-mm="pool" ${running?'disabled':''}>Pool</button>
        </span></div>
      ${showPool?`<div class="at-field" style="margin-top:10px"><div class="fl">Pool address (host:port)${mode==="auto"?" — optional; lets Auto route low hashrate to a pool":""}</div><input class="at-input" id="mPool" placeholder="e.g. pool.coincync.network:3333" value="${S.poolUrl||''}" ${running?'disabled':''}></div>`:""}
      <div class="kv"><span class="k">Worker threads</span>
        <span class="v" style="display:flex;align-items:center;gap:12px">
          <input id="mThreads" type="range" min="1" max="${maxT}" value="${want}" ${running?"disabled":""} style="width:180px;accent-color:var(--gold)">
          <b id="mThreadsVal" class="amt" style="min-width:2ch;text-align:right">${want}</b>
        </span></div>
      <div class="kv"><span class="k">Payout</span><span class="v">${mode==='pool'?'pool-decided · to your login address':'your wallet · stealth address'}</span></div>
      <div style="margin-top:16px"><button class="cta" id="mToggle" ${(!running&&!canMine)?"disabled":""}>${running?"Stop mining":"Start mining"}</button></div>
      ${(!running&&!canMine)?`<div class="note" style="margin-top:12px">Waiting for the node to be reachable…</div>`:""}
      <div class="note" id="mErr" style="margin-top:12px;color:var(--red);display:none"></div>
    </div>
    <p class="note" style="margin-top:16px">Mining runs the native rig as a separate process — nothing hashes in this window. <b>Solo</b> pays you the whole block when you win; <b>Pool</b> earns steady shares so small miners still get paid; <b>Auto</b> measures your hashrate and routes you to whichever actually pays. Rewards land in your ring-private base balance (coinbase amount is public, address is stealth) — Shield them into the Spark pool after h${FORK.toLocaleString()}.</p>
  `;
}
let miningTimer = null;
function patchMining(){
  const m = S.mining;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set("mStatus", m.mining?"Mining":"Idle");
  const sub = document.getElementById("mStatusSub"); if (sub){ sub.textContent = m.mining?(m.mode==="pool"?"pool":"solo"):"stopped"; sub.className = "td "+(m.mining?"g":""); }
  set("mHash", hps(m.hashrate)); set("mHash2", hps(m.hashrate));
  set("mHashSub", m.mining?(m.hashrate>0?"live":"warming up…"):"—");
  const warm = document.getElementById("mWarm"); if (warm) warm.style.display = (m.mining && !(m.hashrate>0)) ? "flex" : "none";
  const poolRunning = m.mining && m.mode==="pool";
  set("mThird", poolRunning ? (m.sharesAccepted||0) : (m.blocksFound||0));
  const tsub = document.getElementById("mThirdSub"); if (tsub) tsub.textContent = poolRunning ? `accepted${m.sharesRejected?` · ${m.sharesRejected} rej`:""}` : "this run";
  set("mNet", m.netHashrate?hps(m.netHashrate)+" H/s":"—");
  const shEl = document.getElementById("mShare"); if (shEl){ shEl.textContent = shareTxt(m); shEl.className = "v "+(shareOf(m)>=0.25?"g":""); }
  set("mDiff", m.difficulty?num(Math.round(m.difficulty)):"—");
  set("mEst", dur(m.estSoloSecs));
  const rec = recLabel(m); const re = document.getElementById("mRec"); if (re){ re.textContent = rec.t; re.className = "v "+rec.cls; }
  const at = document.getElementById("mAutoTxt"); if (at && S.minerMode==="auto") at.innerHTML = autoBanner(m, m.mining);
  if (m.mining) set("mThreadsTv", m.threads);
  const btn = document.getElementById("mToggle");
  if (btn && document.activeElement !== btn) btn.textContent = m.mining?"Stop mining":"Start mining";
}
async function refreshMining(){
  try { const st = await invoke("mining_status"); if (st){ S.mining = st; if (st.maxThreads) S.mining.maxThreads = st.maxThreads; } }
  catch(e){}
  // Smart auto-routing: once a real hashrate is measured, if solo is too slow
  // and a pool is configured, hop to the pool ONCE (no flapping / dataset churn).
  const m = S.mining;
  if (S.minerMode==="auto" && m.mining && !S.autoRouted && m.hashrate>0){
    S.autoRouted = true;
    if (m.recommend==="pool" && (S.poolUrl||"").trim() && m.mode==="solo"){
      try {
        const st = await invoke("start_mining", { threads:S.minerThreads, mode:"pool", poolUrl:S.poolUrl });
        if (st){ S.mining = st; S.autoSwitchedTo = "pool"; }
        if (current==="mining") render("mining");
        return;
      } catch(e){ /* stay solo on failure */ }
    }
  }
  if (current === "mining") patchMining();
}
function wireMining(){
  // mode segmented control (disabled while mining)
  view.querySelectorAll("[data-mm]").forEach(b => b.onclick = () => {
    if (S.mining.mining) return;
    S.minerMode = b.dataset.mm; lsSet("cynchub.minermode", S.minerMode); render("mining");
  });
  const pool = document.getElementById("mPool");
  if (pool) pool.oninput = () => { S.poolUrl = pool.value.trim(); lsSet("cynchub.poolurl", S.poolUrl); };
  const range = document.getElementById("mThreads");
  const val = document.getElementById("mThreadsVal");
  if (range) range.oninput = () => { S.minerThreads = parseInt(range.value,10)||1; if (val) val.textContent = range.value; const tv = document.getElementById("mThreadsTv"); if (tv && !S.mining.mining) tv.textContent = range.value; };
  const btn = document.getElementById("mToggle");
  const err = document.getElementById("mErr");
  if (btn) btn.onclick = async () => {
    if (err){ err.style.display = "none"; err.textContent = ""; }
    const wasMining = S.mining.mining;
    // Auto starts solo then self-routes; Pool needs a URL; Solo as-is.
    const chosen = S.minerMode;
    const backendMode = chosen === "pool" ? "pool" : "solo";
    const poolUrl = (chosen === "pool" || chosen === "auto") ? (S.poolUrl||"") : "";
    if (!wasMining && chosen === "pool" && !poolUrl.trim()){ if (err){ err.textContent = "Enter a pool address (host:port)."; err.style.display = "block"; } return; }
    btn.disabled = true;
    btn.textContent = wasMining ? "Stopping…" : "Starting…";
    try {
      let st;
      if (wasMining){ st = await invoke("stop_mining"); }
      else { S.autoRouted = false; st = await invoke("start_mining", { threads:S.minerThreads, mode:backendMode, poolUrl:poolUrl }); }
      if (st) S.mining = st;
      render("mining");
    } catch(e){
      const msg = (e && (e.message || e.toString())) || "could not change mining";
      if (err){ err.textContent = String(msg); err.style.display = "block"; }
      btn.disabled = false;
      btn.textContent = wasMining ? "Stop mining" : "Start mining";
    }
  };
  if (miningTimer) clearInterval(miningTimer);
  refreshMining();
  miningTimer = setInterval(refreshMining, 2500);
}
function stopMiningPoll(){ if (miningTimer){ clearInterval(miningTimer); miningTimer = null; } }
function nodes(){
  const n = S.node;
  const running = n.running || S.connected;
  const pct = Math.round((running ? (n.progress||0) : 0) * 100);
  const synced = n.isSynced || (S.status === "synced");
  const canStart = !running && n.binAvailable;
  const canStop = n.managed;
  const statusTxt = running ? (synced ? "running · synced" : "running") : (n.binAvailable ? "stopped" : "node not bundled");
  return `
    <div class="pageh"><div class="h1">Nodes</div><div class="sub">Your bundled node · start / stop / sync</div></div>
    <div class="panel"><div class="plabel">Local node</div>
      <div class="kv"><span class="k">Status</span><span class="v ${running?"g":""}" id="nStatus">${statusTxt}</span></div>
      <div class="kv"><span class="k">Chain tip</span><span class="v" id="nTip">${running?num(n.height||S.tip):"—"}</span></div>
      <div class="kv"><span class="k">Peers</span><span class="v" id="nPeers">${running?num(n.peers!=null?n.peers:S.peers):"—"}</span></div>
      <div class="kv"><span class="k">Network</span><span class="v">${S.network||"testnet"}</span></div>
      <div style="margin-top:14px">
        <div class="kv" style="border:0;padding-bottom:6px"><span class="k">Sync</span><span class="v ${synced?"g":""}" id="nPhase">${running?(n.phase||"—"):"—"}</span></div>
        <div class="pbar" style="height:7px;border-radius:4px;background:rgba(255,255,255,.07);overflow:hidden">
          <div id="nBar" style="height:100%;width:${synced?100:pct}%;background:var(--gold);transition:width .4s ease"></div>
        </div>
        <div class="note" id="nSyncEta" style="margin-top:7px;display:none"></div>
      </div>
      <div style="margin-top:18px;display:flex;gap:10px">
        <button class="cta" id="nStart" ${canStart?"":"disabled"} style="${running?"display:none":""}">Start node</button>
        <button class="ghost" id="nStop" ${canStop?"":"disabled"} style="${running&&canStop?"":"display:none"}">Stop node</button>
      </div>
      ${(!n.binAvailable)?`<div class="note" style="margin-top:12px">The node binary isn't bundled with this build.</div>`:""}
      ${(running&&!canStop)?`<div class="note" style="margin-top:12px">This node is running outside CyncHub, so CyncHub won't stop it.</div>`:""}
      ${(!running&&n.managed)?`<div class="note" style="margin-top:12px;color:var(--amber)">The node stopped unexpectedly — click Start to relaunch it.</div>`:""}
      <div class="note" id="nErr" style="margin-top:12px;color:var(--red);display:none"></div>
    </div>
    <p class="note" style="margin-top:16px">The node is bundled with CyncHub — no separate install. First start bootstraps from the signed snapshot (fast-sync) to reach the tip in seconds, then stays current. Logs: <code>%APPDATA%/coincync/cynchub-node.log</code>.</p>
  `;
}
let nodesTimer = null;
function patchNodes(){
  const n = S.node;
  const running = n.running || S.connected;
  const synced = n.isSynced || (S.status === "synced");
  const pct = Math.round((running ? (n.progress||0) : 0) * 100);
  const set = (id,v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  const st = document.getElementById("nStatus");
  if (st){ st.textContent = running ? (synced?"running · synced":"running") : (n.binAvailable?"stopped":"node not bundled"); st.className = "v "+(running?"g":""); }
  set("nTip", running?num(n.height||S.tip):"—");
  set("nPeers", running?num(n.peers!=null?n.peers:S.peers):"—");
  const ph = document.getElementById("nPhase"); if (ph){ ph.textContent = running?(n.phase||"—"):"—"; ph.className = "v "+(synced?"g":""); }
  const bar = document.getElementById("nBar"); if (bar) bar.style.width = (synced?100:pct)+"%";
  const eta = document.getElementById("nSyncEta");
  if (eta){
    if (running && !synced && (n.targetHeight||0) > (n.height||0)){
      const togo = n.targetHeight - n.height;
      let t = `${num(togo)} block${togo===1?"":"s"} to go`;
      if (syncRate > 0) t += ` · ~${num(Math.round(syncRate))} blk/s · ETA ${fmtAge(togo/syncRate)}`;
      eta.textContent = t; eta.style.display = "";
    } else { eta.style.display = "none"; }
  }
  // flip controls without a full re-render unless running-state changed
  const start = document.getElementById("nStart"), stop = document.getElementById("nStop");
  if (start) start.style.display = running?"none":"";
  if (stop) stop.style.display = (running&&n.managed)?"":"none";
}
let syncSample = null; // { h, t } last height/time while syncing
let syncRate = 0;      // measured blocks/sec (EMA of real deltas — never fabricated)
async function refreshNodes(){
  try { const st = await invoke("node_status"); if (st) S.node = st; } catch(e){}
  const n = S.node, now = Date.now();
  if (n && (n.running || S.connected) && !(n.isSynced || S.status==="synced") && (n.targetHeight||0) > (n.height||0)){
    if (syncSample && now > syncSample.t){
      const dh = (n.height||0) - syncSample.h, dt = (now - syncSample.t)/1000;
      if (dh > 0 && dt > 0){ const r = dh/dt; syncRate = syncRate>0 ? syncRate*0.6 + r*0.4 : r; }
    }
    syncSample = { h: n.height||0, t: now };
  } else { syncSample = null; syncRate = 0; }
  if (current === "nodes") patchNodes();
}
function wireNodes(){
  const err = document.getElementById("nErr");
  const fail = (e,fallback) => { const msg=(e&&(e.message||e.toString()))||fallback; if(err){err.textContent=String(msg);err.style.display="block";} };
  const start = document.getElementById("nStart");
  if (start) start.onclick = async () => {
    if (err){ err.style.display="none"; err.textContent=""; }
    start.disabled = true; start.textContent = "Starting…";
    try { const st = await invoke("start_node"); if (st) S.node = st; render("nodes"); }
    catch(e){ fail(e,"could not start the node"); start.disabled=false; start.textContent="Start node"; }
  };
  const stop = document.getElementById("nStop");
  if (stop) stop.onclick = async () => {
    if (err){ err.style.display="none"; err.textContent=""; }
    stop.disabled = true; stop.textContent = "Stopping…";
    try { const st = await invoke("stop_node"); if (st) S.node = st; render("nodes"); }
    catch(e){ fail(e,"could not stop the node"); stop.disabled=false; stop.textContent="Stop node"; }
  };
  if (nodesTimer) clearInterval(nodesTimer);
  refreshNodes();
  nodesTimer = setInterval(refreshNodes, 2500);
}
function stopNodesPoll(){ if (nodesTimer){ clearInterval(nodesTimer); nodesTimer = null; } }
let DX = null; // app_health snapshot
let IX = null; // integrity_check snapshot (consensus fingerprint + build provenance)
function dcheck(label, status, detail){
  const c = status==="ok"?"var(--green)":status==="warn"?"var(--amber)":status==="fail"?"var(--red)":"var(--text-tertiary)";
  const dot = status==="ok"?"●":status==="warn"?"▲":status==="fail"?"✕":"○";
  return `<div class="kv"><span class="k">${label}</span><span class="v" style="color:${c}">${dot} ${detail}</span></div>`;
}
function diagnostics(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const toFork = S.tip == null ? null : Math.max(0, FORK - S.tip);
  const synced = S.status==="synced" || (S.tip!=null && S.target!=null && S.tip>=S.target);
  const d = DX;
  const ix = IX;
  const fpBad = !!(ix && ix.connected && ix.checkable && !ix.fingerprintMatch);
  // overall verdict — a fingerprint mismatch is the most serious (money unsafe).
  const fails = [S.connected, d?d.nodeBin:true, d?d.walletBin:true, d?d.rigBin:true].filter(x=>x===false).length;
  const verdict = fpBad ? {t:"Integrity warning",c:"var(--red)"} : !S.connected ? {t:"Node offline",c:"var(--red)"} : fails? {t:"Issues found",c:"var(--amber)"} : synced ? {t:"All systems go",c:"var(--green)"} : {t:"Syncing",c:"var(--amber)"};
  return `
    <div class="pageh"><div class="h1">Diagnostics</div><div class="sub">Live health checks · <span style="color:${verdict.c}">${verdict.t}</span></div></div>
    <section class="grid2">
      <div class="panel"><div class="plabel">Node</div>
        ${dcheck("Reachable", S.connected?"ok":"fail", S.connected?"connected":"offline")}
        ${dcheck("Sync", S.connected?(synced?"ok":"warn"):"fail", S.connected?(synced?"synced":"syncing "+(S.tip!=null&&S.target?Math.floor(S.tip/S.target*100)+"%":"")):"—")}
        ${dcheck("Chain tip", S.connected?"info":"fail", num(S.tip))}
        ${dcheck("Peers", S.peers>0?"ok":(S.connected?"warn":"fail"), num(S.peers))}
        ${dcheck("Network", "info", S.network||"—")}
        ${dcheck("Shielded pool", forkLive?"ok":"info", forkLive?"live · h"+FORK:"activates h"+FORK+(toFork!=null?` (~${num(toFork)} to go)`:""))}
      </div>
      <div class="panel"><div class="plabel">Wallet</div>
        ${dcheck("Wallet file", d?(d.walletExists?"ok":"warn"):"info", d?(d.walletExists?"present":"none"):"—")}
        ${dcheck("Session", "ok", "unlocked")}
        ${dcheck("Scanned", S.scanned?"ok":"warn", S.scanned?"to block "+num(S.scannedHeight):"not yet")}
        ${dcheck("Outputs tracked", "info", S.scanned?num(S.utxoCount):"—")}
        ${dcheck("RPC auth key", d?(d.rpcKey?"ok":"warn"):"info", d?(d.rpcKey?"loaded":"missing"):"—")}
        ${dcheck("Ghost mode", S.churnOn?"ok":"info", S.churnOn?"running":"off")}
      </div>
    </section>
    <div class="panel" style="margin-top:16px"><div class="plabel">Bundled components</div>
      ${dcheck("Node binary", d?(d.nodeBin?"ok":"fail"):"info", d?(d.nodeBin?"bundled":"missing"):"…")}
      ${dcheck("Wallet binary", d?(d.walletBin?"ok":"fail"):"info", d?(d.walletBin?"bundled":"missing"):"…")}
      ${dcheck("Miner binary", d?(d.rigBin?"ok":"fail"):"info", d?(d.rigBin?"bundled":"missing"):"…")}
      ${dcheck("App version", "info", d?("CyncHub "+d.version):"CyncHub")}
      ${dcheck("Node data dir", "info", d?`<span class="mono" style="font-size:10.5px">${d.dataDir}</span>`:"—")}
    </div>
    <div class="panel" style="margin-top:16px"><div class="plabel">Build integrity · supply chain</div>
      ${ix ? `
        ${dcheck("Consensus fingerprint",
           !ix.connected ? "info" : (!ix.checkable ? "info" : (ix.fingerprintMatch ? "ok" : "fail")),
           !ix.connected ? "node offline" : (!ix.checkable ? ("no baked value for " + (ix.network||"?")) : (ix.fingerprintMatch ? ("matches the live " + ix.network + " network") : "MISMATCH — node running divergent rules")))}
        ${dcheck("Reported", "info", `<span class="mono" style="font-size:10px">${(ix.nodeFingerprint||"—").slice(0,32)}…</span>`)}
        ${dcheck("Node build", (ix.buildDirty || ix.buildProfile==="debug") ? "warn" : "ok", `${ix.buildProfile||"?"}${ix.buildDirty?" · dirty tree":""}${ix.buildCommit?" · "+ix.buildCommit.slice(0,8):""}`)}
      ` : `<div class="note">Checking the node's consensus fingerprint…</div>`}
      <p class="note" style="margin-top:8px">The node must report the exact consensus fingerprint of the live network. A mismatch means the bundled node is stale, swapped, or tampered — its balances can't be trusted.${ix && (ix.buildDirty || ix.buildProfile==="debug") ? " This is a development build (debug/dirty); a signed release will be a clean release build." : ""}</p>
    </div>
    <p class="note" style="margin-top:16px">All checks run locally against your own node + wallet. Green = healthy, amber = attention, red = action needed.</p>
  `;
}
function wireDiagnostics(){
  // refresh ghost-mode state each visit/poll (cheap, never re-renders)
  if (IS_TAURI) invoke("churn_status").then(st => { if (st) S.churnOn = !!st.running; }).catch(()=>{});
  // refresh the integrity snapshot each visit (one get_info; node may have restarted)
  refreshIntegrity();
  if (DX) return; // app_health loaded once per session; periodic render reuses it
  if (!IS_TAURI){ DX = { nodeBin:true, walletBin:true, rigBin:true, rpcKey:true, walletExists:true, dataDir:"%APPDATA%/coincync/cynchub-node", version:"0.1.0" }; return; }
  invoke("app_health").then(d => { if (d){ DX = d; if (current==="diagnostics") render("diagnostics"); } }).catch(()=>{});
}
let bkMode = "idle";   // idle | prompt
let bkWords = null;     // revealed recovery words — held only while shown
function backupPanel(){
  const body = bkMode === "prompt" ? `
    <div style="padding:12px;border:1px solid var(--border);border-radius:var(--r-md);margin-top:4px">
      <div class="note" style="color:var(--amber);margin-bottom:9px">⚠ Your recovery phrase controls all your funds. Never share it, never type it into a website, and make sure no one can see your screen.</div>
      <input class="at-input" id="bkPw" type="password" placeholder="Confirm your wallet password">
      <div style="display:flex;gap:8px;margin-top:9px"><button class="cta" id="bkReveal">Reveal phrase</button><button class="ghost" id="bkCancel">Cancel</button></div>
      <div class="note" id="bkErr" style="margin-top:8px;color:var(--red);display:none"></div>
    </div>`
    : bkWords ? `
    <div style="padding:12px;border:1px solid var(--border);border-radius:var(--r-md);margin-top:4px">
      <div class="note" style="color:var(--amber);margin-bottom:10px">Write these 24 words down <b>in order</b> and keep them offline. Anyone who has them can take your funds.</div>
      <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:7px">${bkWords.map((w,i)=>`<div style="font-family:var(--mono);font-size:12px;padding:6px 9px;background:var(--bg-panel-2);border-radius:6px"><span style="color:var(--text-tertiary)">${i+1}.</span> ${w}</div>`).join("")}</div>
      <div style="display:flex;gap:8px;margin-top:11px"><button class="ghost" id="bkCopy">Copy phrase</button><button class="cta" id="bkHide">I've saved it — hide</button></div>
    </div>`
    : `<div style="margin-top:4px"><button class="ghost" id="bkStart">Reveal recovery phrase</button></div>`;
  return `
    <div class="panel" style="margin-top:16px"><div class="plabel">Backup</div>
      <p class="note" style="margin-bottom:10px">Your 24-word recovery phrase is the only way to restore this wallet. Back it up offline — on paper, not a photo or cloud note.</p>
      ${body}
    </div>`;
}
function settings(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const theme = getTheme();
  const accent = getAccent();
  const lk = getAutoLock();
  const lkTxt = lk === 0 ? "Off" : lk >= 60 ? (lk/60)+" h" : lk+" min";
  return `
    <div class="pageh"><div class="h1">Settings</div><div class="sub">CyncHub · on the CoinCync network</div></div>
    <div class="panel"><div class="plabel">Appearance</div>
      <div class="kv" style="align-items:flex-start"><span class="k">Theme</span>
        <span class="v" style="display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end;max-width:380px">
          ${THEMES.map(t => `<button class="seg ${theme===t.id?'on':''}" data-theme-set="${t.id}">${t.label}</button>`).join("")}
        </span></div>
      <div class="kv" style="align-items:flex-start"><span class="k">Accent</span>
        <span class="v" style="display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end;max-width:380px">
          ${ACCENT_PRESETS.map(a => `<button class="seg ${(a.color?accent===a.color:accent==='theme')?'on':''}" data-accent-set="${a.color||'theme'}">${a.color?`<span style="display:inline-block;width:9px;height:9px;border-radius:50%;background:${a.color};margin-right:6px;vertical-align:-1px"></span>`:''}${a.label}</button>`).join("")}
          <label class="seg" style="display:inline-flex;align-items:center;gap:6px;cursor:pointer">Custom<input type="color" id="accentCustom" value="${currentAccentColor()}" style="width:20px;height:16px;border:none;background:none;padding:0;cursor:pointer"></label>
        </span></div>
      <div class="kv"><span class="k">Density</span><span class="v" style="display:flex;gap:6px">
        ${[["comfortable","Comfortable"],["compact","Compact"]].map(([v,l])=>`<button class="seg ${getPref('density')===v?'on':''}" data-pref="density" data-val="${v}">${l}</button>`).join("")}
      </span></div>
      <div class="kv"><span class="k">UI font</span><span class="v" style="display:flex;gap:6px">
        ${[["system","System"],["rounded","Rounded"],["grotesk","Grotesk"]].map(([v,l])=>`<button class="seg ${getPref('font')===v?'on':''}" data-pref="font" data-val="${v}">${l}</button>`).join("")}
      </span></div>
      <div class="kv"><span class="k">Corners</span><span class="v" style="display:flex;gap:6px">
        ${[["round","Rounded"],["sharp","Sharp"]].map(([v,l])=>`<button class="seg ${getPref('corners')===v?'on':''}" data-pref="corners" data-val="${v}">${l}</button>`).join("")}
      </span></div>
      <div class="kv"><span class="k">Reduce motion</span><span class="v" style="display:flex;gap:6px">
        ${[["full","Off"],["reduce","On"]].map(([v,l])=>`<button class="seg ${getPref('motion')===v?'on':''}" data-pref="motion" data-val="${v}">${l}</button>`).join("")}
      </span></div>
    </div>
    <div class="panel" style="margin-top:16px"><div class="plabel">Security</div>
      <div class="kv"><span class="k">Session</span><span class="v g">unlocked</span></div>
      <div class="kv"><span class="k">Auto-lock when idle</span>
        <span class="v" style="display:flex;gap:6px;flex-wrap:wrap">
          ${[["Off",0],["5 min",5],["15 min",15],["30 min",30],["1 h",60]].map(([t,v])=>`<button class="seg ${lk===v?'on':''}" data-lock-set="${v}">${t}</button>`).join("")}
        </span></div>
      <div class="kv"><span class="k">Current</span><span class="v">${lkTxt}</span></div>
      <div class="kv"><span class="k">Per-transaction cap (${S.unit})</span>
        <span class="v" style="display:flex;gap:6px;align-items:center">
          <input class="at-input" id="capInput" inputmode="decimal" placeholder="none" value="${getSendCap()>0?getSendCap():''}" style="max-width:120px;padding:6px 10px">
          <button class="seg" id="capSave">Set</button>
        </span></div>
      <p class="note" style="margin-top:6px">A hard ceiling on any single send — the review step blocks anything above it. Blank = no cap.</p>
      <div style="margin-top:14px"><button class="ghost" id="lockBtn">Lock now</button></div>
    </div>
    <div class="panel" style="margin-top:16px"><div class="plabel">Two-factor (authenticator)</div>
      <div id="twofaBox"><div class="note">Checking…</div></div>
    </div>
    ${backupPanel()}
    <div class="panel" style="margin-top:16px"><div class="plabel">Privacy · ghost mode</div>
      <div class="kv"><span class="k">Auto-churn</span>
        <span class="v" style="display:flex;align-items:center;gap:10px">
          <span class="${S.churnOn?'g':''}" id="chState">${S.churnOn?"running":"off"}</span>
          <button class="seg ${S.churnOn?'on':''}" id="chToggle">${S.churnOn?"Stop":"Start"}</button>
        </span></div>
      <p class="note" style="margin-top:10px">Churn periodically re-mixes your outputs so chain analysis can't pin a stable balance to you. Runs the native wallet in the background.${forkLive?"":" Most effective once the shielded pool is live."}</p>
      <div class="note" id="chErr" style="margin-top:8px;color:var(--red);display:none"></div>
    </div>
    <div class="panel" style="margin-top:16px"><div class="plabel">About</div>
      <div class="kv"><span class="k">App</span><span class="v">CyncHub v0.1</span></div>
      <div class="kv"><span class="k">Network</span><span class="v">${S.network?"CoinCync "+S.network:"CoinCync testnet"}</span></div>
      <div class="kv"><span class="k">Node</span><span class="v ${S.connected?"g":""}">${S.connected?"connected":"not reachable"}</span></div>
      <div class="kv"><span class="k">Custody</span><span class="v g">non-custodial · keys on device</span></div>
    </div>
  `;
}
function wireSettings(){
  const l = $("#lockBtn"); if (l) l.onclick = lockApp;
  const capSave = $("#capSave");
  if (capSave) capSave.onclick = () => {
    const raw = ($("#capInput").value || "").trim();
    const v = raw === "" ? 0 : (parseFloat(raw) || 0);
    setSendCap(v); capSave.textContent = "Saved ✓"; setTimeout(()=>capSave.textContent="Set", 1400);
  };
  render2fa();
  view.querySelectorAll("[data-theme-set]").forEach(b => b.onclick = () => { setTheme(b.dataset.themeSet); render("settings"); });
  view.querySelectorAll("[data-accent-set]").forEach(b => b.onclick = () => { setAccent(b.dataset.accentSet); render("settings"); });
  view.querySelectorAll("[data-pref]").forEach(b => b.onclick = () => { setPref(b.dataset.pref, b.dataset.val); render("settings"); });
  const ac = document.getElementById("accentCustom");
  if (ac){ ac.oninput = () => setAccent(ac.value); ac.onchange = () => { setAccent(ac.value); render("settings"); }; }
  view.querySelectorAll("[data-lock-set]").forEach(b => b.onclick = () => { setAutoLock(parseInt(b.dataset.lockSet,10)||0); render("settings"); });
  const ct = $("#chToggle"), cerr = $("#chErr");
  if (ct) ct.onclick = async () => {
    if (cerr){ cerr.style.display="none"; cerr.textContent=""; }
    ct.disabled = true; ct.textContent = S.churnOn ? "Stopping…" : "Starting…";
    try { const st = await invoke(S.churnOn?"stop_churn":"start_churn"); S.churnOn = !!(st && st.running); render("settings"); }
    catch(e){ if (cerr){ cerr.textContent = String((e&&e.message)||e); cerr.style.display="block"; } ct.disabled=false; ct.textContent = S.churnOn?"Stop":"Start"; }
  };
  // Backup / seed reveal
  const bkStart = $("#bkStart"); if (bkStart) bkStart.onclick = () => { bkMode = "prompt"; render("settings"); };
  const bkCancel = $("#bkCancel"); if (bkCancel) bkCancel.onclick = () => { bkMode = "idle"; render("settings"); };
  const bkReveal = $("#bkReveal");
  if (bkReveal) bkReveal.onclick = async () => {
    const pw = ($("#bkPw").value || ""); const err = $("#bkErr");
    if (!pw){ if (err){ err.textContent = "Enter your password."; err.style.display = "block"; } return; }
    bkReveal.disabled = true; bkReveal.textContent = "Revealing…";
    try { const words = await invoke("reveal_seed", { password: pw }); bkWords = words; bkMode = "idle"; render("settings"); }
    catch(e){ if (err){ err.textContent = String((e && e.message) || e); err.style.display = "block"; } bkReveal.disabled = false; bkReveal.textContent = "Reveal phrase"; }
  };
  const bkCopy = $("#bkCopy"); if (bkCopy) bkCopy.onclick = async () => { await copyThenClear((bkWords||[]).join(" "), 45); bkCopy.textContent = "Copied ✓ · clears in 45s"; setTimeout(()=>bkCopy.textContent="Copy phrase",2200); };
  const bkHide = $("#bkHide"); if (bkHide) bkHide.onclick = () => { bkWords = null; render("settings"); };
}

// ── router ─────────────────────────────────────────────────────────
// ── Metrics (live "the chain is working" dashboard) ────────────────
let MX = null, metricsTimer = null;
function fmtAge(s){ if (s==null) return "—"; s=Math.max(0,Math.floor(s)); if (s<60) return s+"s"; if (s<3600) return Math.floor(s/60)+"m "+(s%60)+"s"; return Math.floor(s/3600)+"h "+Math.floor((s%3600)/60)+"m"; }
function metrics(){
  const m = MX;
  if (!m){
    return `<div class="pageh"><div class="h1">Metrics</div><div class="sub">Live chain activity from your node</div></div>
      <div class="panel"><div class="at-empty" style="padding:28px 8px">${I.clock}<p>Reading live metrics from your node…</p></div></div>`;
  }
  const sl = !m.connected ? {txt:"node offline",cls:""} : (m.isSynced?{txt:"synced · live",cls:"g"}:{txt:"syncing",cls:""});
  const diffTxt = m.difficulty ? num(Math.round(m.difficulty)) : "—";
  const bt = m.avgBlockSecs>0 ? Math.round(m.avgBlockSecs)+"s" : "—";
  const btCls = m.avgBlockSecs>0 && m.avgBlockSecs<=180 ? "g" : "";
  const supplyTxt = m.supply==null?"—":(m.supply>=1e6?(m.supply/1e6).toFixed(2)+" M":Math.round(m.supply).toLocaleString());
  const now = Math.floor(Date.now()/1000);
  const feed = (m.blocks||[]).map((b,idx)=>{
    const age = b.timestamp ? (now - b.timestamp) : null;
    return `<div class="kv"><span class="k"><b style="font-family:var(--mono);color:var(--gold-200)">#${Number(b.height).toLocaleString()}</b>${idx===0?' <span class="atag">newest</span>':''}</span><span class="v">${fmtAge(age)} ago · ${b.txCount} tx</span></div>`;
  }).join("");
  return `
    <div class="pageh"><div class="h1">Metrics</div><div class="sub">Live chain activity from your node · <span class="${sl.cls}">${sl.txt}</span></div></div>
    <div class="tiles">
      <div class="tile"><div class="tk">Chain tip</div><div class="tv">${num(m.height)}</div><div class="td">tip ${fmtAge(m.tipAgeSecs)} old</div></div>
      <div class="tile"><div class="tk">Block time</div><div class="tv ${btCls}">${bt}</div><div class="td">target ~120s</div></div>
      <div class="tile"><div class="tk">Difficulty</div><div class="tv" style="font-size:20px">${diffTxt}</div><div class="td">retargets each block</div></div>
      <div class="tile"><div class="tk">Network hashrate</div><div class="tv">${hps(m.netHashrate)} <span style="font-size:13px;color:var(--text-tertiary)">H/s</span></div><div class="td">est. from difficulty</div></div>
    </div>
    <div class="tiles">
      <div class="tile"><div class="tk">Peers</div><div class="tv">${num(m.peers)}</div><div class="td">connected</div></div>
      <div class="tile"><div class="tk">Mempool</div><div class="tv">${num(m.mempool)}</div><div class="td">pending tx</div></div>
      <div class="tile"><div class="tk">Supply</div><div class="tv" style="font-size:20px">${supplyTxt}</div><div class="td">${S.unit}</div></div>
      <div class="tile"><div class="tk">Anon set</div><div class="tv">${num(m.anonSet)}</div><div class="td">${m.ringSize?'ring '+m.ringSize:'—'}</div></div>
    </div>
    <div class="panel"><div class="plabel">Latest blocks</div>${feed || `<div class="note">waiting for the next block…</div>`}</div>
    <p class="note" style="margin-top:16px">Live from your node, refreshed every few seconds — public chain state only; your wallet stays private.</p>
  `;
}
async function refreshMetrics(){
  try { const m = await invoke("get_metrics"); if (m) MX = m; } catch(e){}
  if (current === "metrics") view.innerHTML = metrics();
}
function wireMetrics(){
  if (metricsTimer) clearInterval(metricsTimer);
  refreshMetrics();
  metricsTimer = setInterval(refreshMetrics, 4000);
}
function stopMetricsPoll(){ if (metricsTimer){ clearInterval(metricsTimer); metricsTimer = null; } }

// ── Privacy Center ─────────────────────────────────────────────────
function privacy(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const toFork = S.tip == null ? null : Math.max(0, FORK - S.tip);
  const ring = S.ringSize || 16;
  const facts = [
    ["Ring signatures (CLSAG)", `ring size ${ring}`, `Every input is signed together with ${ring-1} decoy outputs, so the ledger can't tell which one you actually spent.`],
    ["Stealth addresses", "one-time, per payment", "Each payment is received on a fresh one-time address derived on-chain. Your public address never appears in a transaction."],
    ["Confidential amounts", "Pedersen commitments", "Transaction amounts are cryptographically committed — hidden from everyone except the sender and the receiver."],
    ["Transparent mode", "none · by protocol", "CoinCync has no transparent transactions. Privacy is the only mode — there is nothing to switch on and nothing to forget."],
  ];
  const factRows = facts.map(([k,v,note])=>`
    <div class="kv"><span class="k" style="display:flex;align-items:center;gap:8px"><span style="color:var(--green);display:inline-flex;width:16px">${I.check}</span>${k}</span><span class="v g">${v}</span></div>
    <p class="note" style="margin:-2px 0 12px 24px">${note}</p>`).join("");

  const sparkPanel = forkLive
    ? `<div class="panel" style="margin-top:16px"><div class="plabel">Spark shielded pool · live</div>
         <p class="note">The shielded pool is active. Shielding your balance joins it to the largest shared anonymity set${S.anonSet!=null?` (${num(S.anonSet)} outputs)`:""}, on top of the ring-private base layer.</p>
         <div style="margin-top:10px"><button class="seg" data-screen="shield">Open Shield</button></div></div>`
    : `<div class="panel" style="margin-top:16px"><div class="plabel">Spark shielded pool · pending</div>
         <p class="note">A second, even larger anonymity layer activates at <b>h${FORK.toLocaleString()}</b>${toFork!=null?` (~${num(toFork)} blocks away)`:""}. Until then your funds are already ring-private — the pool is an upgrade, not a prerequisite.</p></div>`;

  return `
    <div class="pageh"><div class="h1">Privacy Center</div><div class="sub">Privacy is mandatory on CoinCync — always on, enforced by the protocol</div></div>
    <div class="nudge"><div class="ni">${I.shield}</div>
      <div class="nt">Every transaction hides the <b>sender</b>, the <b>recipient</b> and the <b>amount</b>. There is no way to send in the clear — which is exactly how CoinCync avoids the opt-in-privacy trap, where almost no one ends up actually private.</div></div>
    <div class="panel"><div class="plabel">Guaranteed by protocol</div>${factRows}</div>
    ${privacyHealthPanel()}
    <div class="panel" style="margin-top:16px"><div class="plabel">Ghost mode · auto-churn</div>
      <div class="kv"><span class="k">Background re-mixing</span>
        <span class="v" style="display:flex;align-items:center;gap:10px">
          <span class="${S.churnOn?'g':''}" id="pvState">${S.churnOn?"running":"off"}</span>
          <button class="seg ${S.churnOn?'on':''}" id="pvChurn">${S.churnOn?"Stop":"Start"}</button>
        </span></div>
      <p class="note" style="margin-top:10px">Ghost mode periodically re-mixes your outputs so long-term chain analysis can't pin a stable balance to you. It runs the native wallet quietly in the background.${forkLive?"":" It becomes most effective once the shielded pool is live."}</p>
      <div class="note" id="pvErr" style="margin-top:8px;color:var(--red);display:none"></div>
    </div>
    ${sparkPanel}
    <p class="note" style="margin-top:16px">These guarantees come from CoinCync's consensus rules (Constitution Article III — mandatory privacy), not from this app. CyncHub only surfaces them.</p>
  `;
}
function wirePrivacy(){
  view.querySelectorAll("[data-pha]").forEach(b => b.onclick = async (e) => {
    e.stopPropagation();
    const act = b.dataset.pha;
    if (act === "shield"){ render("shield"); return; }
    if (act === "churn"){
      b.disabled = true; b.textContent = "…";
      try { const st = await invoke("start_churn"); S.churnOn = !!(st && st.running); }
      catch(err){ b.disabled = false; b.textContent = "Turn on"; return; }
      render("privacy");
    }
  });
  const ct = $("#pvChurn"), cerr = $("#pvErr");
  if (ct) ct.onclick = async () => {
    if (cerr){ cerr.style.display="none"; cerr.textContent=""; }
    ct.disabled = true; ct.textContent = S.churnOn ? "Stopping…" : "Starting…";
    try { const st = await invoke(S.churnOn?"stop_churn":"start_churn"); S.churnOn = !!(st && st.running); render("privacy"); }
    catch(e){ if (cerr){ cerr.textContent = String((e&&e.message)||e); cerr.style.display="block"; } ct.disabled=false; ct.textContent = S.churnOn?"Stop":"Start"; }
  };
}

const SCREENS = { vault, send, receive, shield, lens, attest, swap, mining, nodes, metrics, diagnostics, privacy, settings };
function render(name){
  current = name;
  const fn = SCREENS[name] || vault;
  view.innerHTML = fn();
  document.querySelectorAll(".nav").forEach(n => n.classList.toggle("active", n.dataset.screen === name));
  if (name !== "mining") stopMiningPoll();
  if (name !== "nodes") stopNodesPoll();
  if (name !== "metrics") stopMetricsPoll();
  if (name !== "settings"){ bkWords = null; bkMode = "idle"; } // never keep the seed around off-screen
  if (name === "vault") wireVault();
  if (name === "send") wireSend();
  if (name === "receive") wireReceive();
  if (name === "shield") wireShield();
  if (name === "attest") wireAttest();
  if (name === "mining") wireMining();
  if (name === "nodes") wireNodes();
  if (name === "metrics") wireMetrics();
  if (name === "diagnostics") wireDiagnostics();
  if (name === "privacy") wirePrivacy();
  if (name === "settings") wireSettings();
  // in-content links that navigate (e.g. Vault's Attest card)
  view.querySelectorAll("[data-screen]").forEach(el => el.onclick = () => render(el.dataset.screen));
}
document.querySelectorAll(".nav[data-screen]").forEach(n => n.onclick = () => render(n.dataset.screen));

// ── auth gate: unlock / create / restore (desktop app only) ─────────
const authEl = (() => { const d = document.createElement("div"); d.className = "auth"; d.style.display = "none"; document.body.appendChild(d); return d; })();
const authLogo = `<div class="auth-logo">C</div>`;
// ── TOTP 2FA (RFC 6238, verified in-webview via WebCrypto HMAC-SHA1) ─
// Gates the APP, never the funds: the 24-word seed restores the wallet in any
// client, so a lost authenticator can never lock anyone out of their money.
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function b32encode(bytes){ let bits=0,val=0,out=""; for(const b of bytes){ val=(val<<8)|b; bits+=8; while(bits>=5){ out+=B32[(val>>>(bits-5))&31]; bits-=5; } } if(bits>0) out+=B32[(val<<(5-bits))&31]; return out; }
function b32decode(str){ const s=(str||"").toUpperCase().replace(/[\s=]/g,""); let bits=0,val=0; const out=[]; for(const c of s){ const i=B32.indexOf(c); if(i<0) continue; val=(val<<5)|i; bits+=5; if(bits>=8){ out.push((val>>>(bits-8))&0xff); bits-=8; } } return new Uint8Array(out); }
function newTotpSecret(){ const r=new Uint8Array(20); crypto.getRandomValues(r); return b32encode(r); }
function totpUri(secret, label){ return `otpauth://totp/CyncHub:${encodeURIComponent(label||"wallet")}?secret=${secret}&issuer=CyncHub&digits=6&period=30&algorithm=SHA1`; }
async function totpCode(secret, forTimeSec){
  const key = b32decode(secret);
  const counter = Math.floor((forTimeSec==null ? Date.now()/1000 : forTimeSec) / 30);
  const buf = new ArrayBuffer(8), dv = new DataView(buf);
  dv.setUint32(0, Math.floor(counter / 0x100000000)); dv.setUint32(4, counter >>> 0);
  const ck = await crypto.subtle.importKey("raw", key, { name:"HMAC", hash:"SHA-1" }, false, ["sign"]);
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", ck, buf));
  const off = mac[mac.length-1] & 0xf;
  const bin = ((mac[off]&0x7f)<<24) | ((mac[off+1]&0xff)<<16) | ((mac[off+2]&0xff)<<8) | (mac[off+3]&0xff);
  return String(bin % 1000000).padStart(6, "0");
}
async function totpVerify(secret, code){
  const c = (code||"").replace(/\D/g,"");
  if (!/^\d{6}$/.test(c) || !secret) return false;
  const now = Date.now()/1000;
  for (const w of [-1,0,1]){ try { if (await totpCode(secret, now + w*30) === c) return true; } catch { return false; } }
  return false;
}
function totpAvailable(){ return !!(window.crypto && crypto.subtle && crypto.getRandomValues); }
// After a correct password, require the 2FA code if 2FA is enabled.
async function afterUnlock(){
  try { const st = await invoke("totp_status"); if (st && st.enabled){ showAuth("totp"); return; } } catch {}
  enterApp();
}
// Settings → Two-factor panel: enable (scan + confirm a code) or disable (code).
async function render2fa(){
  const box = document.getElementById("twofaBox"); if (!box) return;
  if (!totpAvailable()){ box.innerHTML = `<div class="note" style="color:var(--amber)">This build can't run 2FA (no secure crypto available in the webview).</div>`; return; }
  let enabled = false; try { const st = await invoke("totp_status"); enabled = !!(st && st.enabled); } catch {}
  const msgFn = () => { const m = document.getElementById("twofaMsg"); return (t,c)=>{ if(m){ m.style.display="block"; m.style.color=c; m.textContent=t; } }; };
  if (enabled){
    box.innerHTML = `<div class="kv"><span class="k">Status</span><span class="v g">● enabled</span></div>
      <p class="note" style="margin-top:8px">A 6-digit code is required to unlock CyncHub and to confirm a <b>large</b> send (over half your spendable balance).</p>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center"><input class="at-input" id="twofaOff" inputmode="numeric" maxlength="6" placeholder="code to disable" style="max-width:150px;padding:7px 11px"><button class="seg" id="twofaDisable">Disable 2FA</button></div>
      <div class="note" id="twofaMsg" style="margin-top:8px;display:none"></div>`;
    const btn = document.getElementById("twofaDisable");
    if (btn) btn.onclick = async () => {
      const show = msgFn();
      const code = (document.getElementById("twofaOff").value || "").trim();
      let secret = null; try { secret = await invoke("totp_get"); } catch {}
      if (!secret || !(await totpVerify(secret, code))){ show("Enter a current code to disable 2FA.", "var(--red)"); return; }
      try { await invoke("totp_disable"); render2fa(); } catch(e){ show(String((e&&e.message)||e), "var(--red)"); }
    };
    return;
  }
  box.innerHTML = `<p class="note">Add a second factor with any authenticator app (Google Authenticator, Authy…). Codes are generated on your phone and verified on this device — no server, no email or phone number. It gates the app, not your funds; your seed always restores the wallet.</p>
    <button class="seg" id="twofaStart" style="margin-top:10px">Set up 2FA</button>`;
  const start = document.getElementById("twofaStart");
  if (start) start.onclick = async () => {
    const secret = newTotpSecret();
    const uri = totpUri(secret, (S.network || "testnet"));
    let qr = ""; try { qr = await invoke("generate_qr_svg", { payload: uri }); } catch {}
    box.innerHTML = `
      <p class="note">Scan this in your authenticator app (or type the secret in by hand), then enter the 6-digit code it shows to confirm.</p>
      ${qr?`<div style="display:flex;justify-content:center;margin:12px 0"><div style="width:168px;height:168px;background:#fff;border-radius:8px;padding:8px;box-sizing:border-box">${qr}</div></div>`:""}
      <div class="kv"><span class="k">Secret</span><span class="v mono" style="font-size:11px;word-break:break-all">${secret}</span></div>
      <div style="margin-top:10px;display:flex;gap:8px;align-items:center"><input class="at-input" id="twofaCode" inputmode="numeric" maxlength="6" placeholder="6-digit code" style="max-width:150px;padding:7px 11px"><button class="cta" id="twofaConfirm" style="padding:8px 16px">Confirm &amp; enable</button></div>
      <div class="note" id="twofaMsg" style="margin-top:8px;display:none"></div>
      <p class="note" style="margin-top:10px">Keep this secret and your 24-word seed safe. Lose the authenticator → restore the wallet from seed in a fresh install.</p>`;
    const conf = document.getElementById("twofaConfirm");
    if (conf) conf.onclick = async () => {
      const show = msgFn();
      const code = (document.getElementById("twofaCode").value || "").trim();
      if (!(await totpVerify(secret, code))){ show("That code didn't match — check your authenticator and try again.", "var(--red)"); return; }
      try { await invoke("totp_set", { secret }); show("2FA enabled ✓", "var(--green)"); setTimeout(render2fa, 900); }
      catch(e){ show(String((e&&e.message)||e), "var(--red)"); }
    };
  };
}

function aerr(m){ const e = document.getElementById("aerr"); if (e) e.textContent = m || ""; }
function showAuth(mode, data){ authEl.style.display = "grid"; authEl.innerHTML = authHtml(mode, data); wireAuth(mode); const i = authEl.querySelector("input,textarea"); if (i) i.focus(); }
function hideAuth(){ authEl.style.display = "none"; authEl.innerHTML = ""; }

let onboardSeed = null;   // 24 words during first-run (cleared after verify)
let verifyState = null;   // { positions:[], options:{pos:[words]}, picks:{} }
function buildVerify(){
  const words = onboardSeed || [];
  if (words.length < 12){ enterApp(); return; }
  const idxs = [];
  while (idxs.length < 3 && idxs.length < words.length){ const r = Math.floor(Math.random()*words.length); if (!idxs.includes(r)) idxs.push(r); }
  idxs.sort((a,b)=>a-b);
  const options = {};
  idxs.forEach(pos => {
    const opts = new Set([words[pos]]);
    let guard = 0;
    while (opts.size < 4 && guard++ < 200){ opts.add(words[Math.floor(Math.random()*words.length)]); }
    options[pos] = Array.from(opts).sort(()=>Math.random()-0.5);
  });
  verifyState = { positions: idxs, options, picks: {} };
}
function authHtml(mode, data){
  if (mode === "unlock") return `<div class="auth-card">${authLogo}<div class="auth-eyebrow">Welcome back</div><div class="auth-title">Unlock CyncHub</div>
    <div class="auth-err" id="aerr"></div>
    <input class="auth-input" id="apw" type="password" placeholder="Wallet password">
    <button class="auth-btn" id="abtn">Unlock</button>
    <div class="auth-foot">Non-custodial · keys on device · testnet</div></div>`;
  if (mode === "onboard") return `<div class="auth-card">${authLogo}<div class="auth-eyebrow">Welcome to</div><div class="auth-title">CyncHub</div>
    <div class="auth-lead">Your private CoinCync wallet. Keys are generated and kept on this device — no account, no custody.</div>
    <button class="auth-btn" id="acreate">Create a new wallet</button>
    <div class="auth-alt"><a id="arestore">Restore from seed phrase</a></div></div>`;
  if (mode === "create") return `<div class="auth-card">${authLogo}<div class="auth-title">Create wallet</div>
    <div class="auth-err" id="aerr"></div>
    <input class="auth-input" id="apw" type="password" placeholder="Choose a password (8+ characters)">
    <input class="auth-input" id="apw2" type="password" placeholder="Confirm password">
    <button class="auth-btn" id="abtn">Create</button>
    <div class="auth-alt"><a id="aback">← back</a></div></div>`;
  if (mode === "restore") return `<div class="auth-card">${authLogo}<div class="auth-title">Restore wallet</div>
    <div class="auth-err" id="aerr"></div>
    <textarea class="auth-input" id="aseed" rows="3" placeholder="Your 12–24 word seed phrase"></textarea>
    <input class="auth-input" id="apw" type="password" placeholder="Choose a password">
    <button class="auth-btn" id="abtn">Restore</button>
    <div class="auth-alt"><a id="aback">← back</a></div></div>`;
  if (mode === "seed"){
    const words = data ? data.split(/\s+/).filter(Boolean) : (onboardSeed || []);
    onboardSeed = words;
    const grid = words.length ? `<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:7px;margin-bottom:14px;text-align:left">${words.map((w,i)=>`<div style="font-family:var(--mono);font-size:12px;padding:6px 8px;background:var(--bg-panel-2);border-radius:6px"><span style="color:var(--text-tertiary)">${i+1}.</span> ${w}</div>`).join("")}</div>` : `<div class="auth-seed">(seed unavailable)</div>`;
    return `<div class="auth-card" style="max-width:460px">${authLogo}<div class="auth-title">Your recovery phrase</div>
    <div class="auth-warn">Write these ${words.length||24} words down <b>in order</b> and keep them offline. They are the ONLY way to recover your wallet — CyncHub cannot reset it.</div>
    ${grid}
    <button class="auth-btn" id="adone">I've written it down → verify</button></div>`;
  }
  if (mode === "totp") return `<div class="auth-card">${authLogo}<div class="auth-eyebrow">Two-factor</div><div class="auth-title">Enter your code</div>
    <div class="auth-err" id="aerr"></div>
    <input class="auth-input" id="a2fa" inputmode="numeric" maxlength="6" placeholder="6-digit authenticator code" autocomplete="one-time-code">
    <button class="auth-btn" id="abtn">Verify</button>
    <div class="auth-foot">Lost your authenticator? Your 24-word seed restores this wallet in a fresh install — your funds are safe.</div></div>`;
  if (mode === "verify"){
    const v = verifyState || { positions:[], options:{} };
    const blocks = v.positions.map(pos => `
      <div style="margin-bottom:14px;text-align:left">
        <div style="font-family:var(--mono);font-size:11.5px;color:var(--text-secondary);margin-bottom:7px">Select word #${pos+1}</div>
        <div style="display:flex;gap:7px;flex-wrap:wrap">${(v.options[pos]||[]).map(w=>`<button class="seg vword" data-pos="${pos}" data-word="${w}">${w}</button>`).join("")}</div>
      </div>`).join("");
    return `<div class="auth-card" style="max-width:460px">${authLogo}<div class="auth-title">Confirm your backup</div>
    <div class="auth-err" id="aerr"></div>
    <div class="auth-warn" style="margin-bottom:16px">Prove you saved your phrase — pick the right word for each position.</div>
    ${blocks}
    <button class="auth-btn" id="avdone">Finish setup</button>
    <div class="auth-alt"><a id="avback">← show my phrase again</a></div></div>`;
  }
  return "";
}

function wireAuth(mode){
  if (mode === "unlock"){
    const go = async () => { const pw = document.getElementById("apw").value; if (!pw){ aerr("enter your password"); return; }
      aerr(""); try { await invoke("unlock_wallet", { password: pw }); afterUnlock(); } catch(e){ aerr("invalid password"); } };
    document.getElementById("abtn").onclick = go;
    document.getElementById("apw").onkeydown = e => { if (e.key === "Enter") go(); };
  } else if (mode === "totp"){
    const go = async () => {
      const code = (document.getElementById("a2fa").value || "").trim();
      aerr("");
      let secret = null; try { secret = await invoke("totp_get"); } catch {}
      if (!secret){ enterApp(); return; } // 2FA secret gone → never lock the user out
      if (await totpVerify(secret, code)) enterApp();
      else aerr("that code isn't valid — check your authenticator");
    };
    document.getElementById("abtn").onclick = go;
    document.getElementById("a2fa").onkeydown = e => { if (e.key === "Enter") go(); };
  } else if (mode === "onboard"){
    document.getElementById("acreate").onclick = () => showAuth("create");
    document.getElementById("arestore").onclick = () => showAuth("restore");
  } else if (mode === "create"){
    document.getElementById("aback").onclick = () => showAuth("onboard");
    document.getElementById("abtn").onclick = async () => {
      const pw = document.getElementById("apw").value, pw2 = document.getElementById("apw2").value;
      if (pw.length < 8){ aerr("password must be at least 8 characters"); return; }
      if (pw !== pw2){ aerr("passwords don't match"); return; }
      aerr("Creating…"); try { const seed = await invoke("create_wallet", { password: pw }); showAuth("seed", seed); }
      catch(e){ aerr(String((e && e.message) || e)); }
    };
  } else if (mode === "restore"){
    document.getElementById("aback").onclick = () => showAuth("onboard");
    document.getElementById("abtn").onclick = async () => {
      const seed = document.getElementById("aseed").value.trim(), pw = document.getElementById("apw").value;
      if (seed.split(/\s+/).filter(Boolean).length < 12){ aerr("enter your 12–24 word seed"); return; }
      if (pw.length < 8){ aerr("password must be at least 8 characters"); return; }
      aerr("Restoring…"); try { await invoke("restore_wallet", { seed, password: pw }); enterApp(); }
      catch(e){ aerr(String((e && e.message) || e)); }
    };
  } else if (mode === "seed"){
    document.getElementById("adone").onclick = () => { buildVerify(); showAuth("verify"); };
  } else if (mode === "verify"){
    authEl.querySelectorAll(".vword").forEach(b => b.onclick = () => {
      const pos = b.dataset.pos;
      verifyState.picks[pos] = b.dataset.word;
      authEl.querySelectorAll(`.vword[data-pos="${pos}"]`).forEach(x => x.classList.remove("on"));
      b.classList.add("on"); aerr("");
    });
    document.getElementById("avback").onclick = () => showAuth("seed");
    document.getElementById("avdone").onclick = () => {
      const v = verifyState, words = onboardSeed || [];
      const allRight = v && v.positions.length && v.positions.every(pos => v.picks[pos] === words[pos]);
      if (!allRight){ aerr("That's not quite right — check your written phrase and try again."); buildVerify(); showAuth("verify"); return; }
      onboardSeed = null; verifyState = null; enterApp();
    };
  }
}

function lockApp(){ if (pollTimer){ clearInterval(pollTimer); pollTimer = null; } stopMiningPoll(); stopNodesPoll(); stopMetricsPoll(); bkWords = null; bkMode = "idle"; if (idleTimer){ clearTimeout(idleTimer); idleTimer = null; } document.body.dataset.locked = "1"; invoke("lock_wallet").catch(()=>{}); S.scanned=false; S.balBaseline=false; S.total=S.transparent=S.shielded=0; IX = null; updateIntegrityBanner(); document.body.classList.remove("reveal"); showAuth("unlock"); }

// Pull public chain state from the node (works before/without a wallet).
async function pollChain(){
  try {
    const ci = await invoke("get_chain_info");
    if (ci){
      S.connected = !!ci.connected;
      S.tip = ci.height ?? S.tip;
      if (typeof ci.peers === "number") S.peers = ci.peers;
      if (ci.targetHeight) S.target = ci.targetHeight;
      if (typeof ci.anonSet === "number") S.anonSet = ci.anonSet;
      if (typeof ci.ringSize === "number") S.ringSize = ci.ringSize;
      if (ci.status) S.status = ci.status;
      if (ci.network) S.network = ci.network;
      if (typeof ci.supply === "number") S.supply = ci.supply;
    }
  } catch(e){ S.connected = false; }
}

// Scan the wallet for real balances (needs an unlocked wallet).
async function pollWallet(){
  try {
    const b = await invoke("scan_wallet");
    if (b){
      S.transparent = b.unlocked || 0;                        // spendable transparent
      S.pending = Math.max(0, (b.total||0) - (b.unlocked||0)); // locked / unconfirmed transparent
      S.utxoCount = b.utxoCount || 0;
      if (b.height) S.scannedHeight = b.height;
      S.scanned = true;
      S.total = (b.total||0) + (S.shielded||0);
    }
  } catch(e){ console.warn("[scan_wallet]", e); }
  // Real shielded-pool balance (honestly 0 until the h29000 fork activates it).
  try {
    const sh = await invoke("shielded_balance");
    if (sh){
      S.shielded = sh.balance || 0;
      S.shieldedNotes = sh.notes || 0;
      S.shieldedActive = !!sh.active;
      S.total = (S.transparent||0) + (S.pending||0) + S.shielded;
    }
  } catch(e){ /* pre-fork / locked: leave shielded at 0 */ }
  // Incoming-payment detection: a balance increase since the last scan means
  // funds arrived — alert the user (the first scan just sets the baseline).
  if (S.scanned){
    if (S.balBaseline && S.total > S.prevTotal + 1e-9){
      const delta = S.total - S.prevTotal;
      showToast(`<b>Received +${f(delta)} ${S.unit}</b><br>Your balance just updated.`, "in");
    }
    S.prevTotal = S.total;
    S.balBaseline = true;
  }
}

let pollTimer = null, walletPollTick = 0;
function startPolling(){
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    await pollChain();
    // re-scan the wallet every ~25s so the balance stays live + receipts alert
    walletPollTick = (walletPollTick + 1) % 5;
    if (walletPollTick === 0){
      refreshIntegrity(); // re-check the node's fingerprint every ~25s
      if (S.scanned){
        await pollWallet();
        if (current === "vault") render("vault");
      }
    }
    // only re-render the live network screens so we don't disturb inputs
    if (["lens","nodes","diagnostics","vault","settings"].includes(current)) render(current);
  }, 5000);
}

// App-wide integrity banner — screams on a consensus-fingerprint mismatch from
// every screen, not just Diagnostics (a forked/tampered node = funds unsafe).
const integrityBar = (() => { const d = document.createElement("div"); d.id = "integrityBar"; d.className = "ibar"; d.style.display = "none"; document.body.appendChild(d); return d; })();
function updateIntegrityBanner(){
  const bad = !!(IX && IX.connected && IX.checkable && !IX.fingerprintMatch);
  if (!bad){ integrityBar.style.display = "none"; integrityBar.innerHTML = ""; document.body.classList.remove("has-ibar"); return; }
  document.body.classList.add("has-ibar");
  integrityBar.style.display = "flex";
  integrityBar.innerHTML = `<span>⚠ <b>Node integrity warning</b> — your node reports different consensus rules than the live network. It may be stale, swapped, or tampered — <b>don't trust balances and don't send funds.</b></span><button class="ibar-x" id="ibarDiag">Open Diagnostics</button>`;
  const b = document.getElementById("ibarDiag"); if (b) b.onclick = () => render("diagnostics");
}
async function refreshIntegrity(){
  if (!IS_TAURI) return;
  try { const x = await invoke("integrity_check"); if (x){ IX = x; updateIntegrityBanner(); if (current === "diagnostics") render("diagnostics"); } } catch {}
}

async function enterApp(){
  hideAuth();
  document.body.dataset.locked = "0";
  // restore per-device mining preferences
  S.minerMode = (["auto","solo","pool"].includes(lsGet("cynchub.minermode","auto"))) ? lsGet("cynchub.minermode","auto") : "auto";
  S.poolUrl = lsGet("cynchub.poolurl","") || "";
  await pollChain();
  render("vault");
  startPolling();
  refreshIntegrity();
  bindIdleReset(); armIdleLock();
  // reflect a churn process that's already running (e.g. after unlock)
  invoke("churn_status").then(st => { if (st) S.churnOn = !!st.running; }).catch(()=>{});
  // wallet scan can take a moment; fire it and refresh when it lands
  pollWallet().then(() => { if (current === "vault" || current === "diagnostics") render(current); });
}

async function boot(){
  if (!IS_TAURI){ enterApp(); return; } // browser preview: skip auth, show the design with mock data
  let exists = true;
  try { exists = !!(await invoke("wallet_exists")); } catch(e){}
  showAuth(exists ? "unlock" : "onboard");
}
boot();
