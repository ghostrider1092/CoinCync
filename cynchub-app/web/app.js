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
    case "wallet_exists":  return true;
    case "scan_wallet":    return { total:0, unlocked:0, height:1068, utxoCount:0 };
    case "get_wallet_address": return "cync1q…demo…x0qT9";
    case "disclose_balance":   return { kind:"balance", artifact:"zkCYNC1"+"deadbeefcafef00d".repeat(10) };
    case "disclose_scoped_view_key": return { kind:"scoped-view-key", artifact: JSON.stringify({from:0,to:S.tip,view_secret:"f805b0…",view_public:"866012…"}) };
    case "send_transaction":   return "mock"+"deadbeef".repeat(8);
    case "new_subaddress":     return "tCYNCsub"+"1a2b3c".repeat(6)+"demo";
    case "integrated_address": return "tCYNCint"+"9f8e7d".repeat(6)+"demo";
    case "list_received":      return [];
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
  { id:"midnight", label:"Midnight" },
  { id:"slate", label:"Slate" },
  { id:"sepia", label:"Sepia" },
];
const THEME_IDS = THEMES.map(t => t.id);
function getTheme(){ const t = lsGet("cynchub.theme","dark"); return THEME_IDS.includes(t) ? t : "dark"; }
function applyTheme(t){ if (!THEME_IDS.includes(t)) t = "dark"; document.documentElement.setAttribute("data-theme", t); }
function setTheme(t){ if (!THEME_IDS.includes(t)) t = "dark"; lsSet("cynchub.theme", t); applyTheme(t); }
function getAutoLock(){ const n = parseInt(lsGet("cynchub.autolock","15"),10); return Number.isFinite(n) && n>=0 ? n : 15; } // minutes; 0 = off
function setAutoLock(m){ lsSet("cynchub.autolock", m); armIdleLock(); }
applyTheme(getTheme());

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
         <div class="nt">The shielded pool activates at <b>h${FORK.toLocaleString()}</b>${toFork!=null?` — <b class="amt">~${toFork.toLocaleString()}</b> blocks away`:""}. Until then balances are transparent.</div></div>`
    : (S.transparent > 0
        ? `<div class="nudge"><div class="ni">${I.shieldPlain}</div>
             <div class="nt"><b class="amt">${f(S.transparent)} ${S.unit}</b> is transparent — Shield it to join the anonymity set${S.anonSet!=null?` (${num(S.anonSet)} outputs)`:""}.</div></div>`
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
          <div class="split"><span class="sk">${I.circle} Transparent</span><div class="sv amt">${f(S.transparent)}</div></div>
          <div class="split shield"><span class="sk">${I.lock} Shielded</span><div class="sv amt">${f(S.shielded)}</div></div>
        </div>
        <div class="meter"><div class="ml"><span>Privacy coverage</span><b>${cov}% shielded</b></div><div class="bar"><i style="width:${cov}%"></i></div></div>
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
        <div class="kv"><span class="k">${I.circle}Transparent · spendable now</span><span class="v amt">${f(S.transparent)}</span></div>
        <div class="kv"><span class="k">${I.lock}Shielded · private</span><span class="v gold amt">${f(S.shielded)}</span></div>
        <div class="kv"><span class="k">${I.clock}Pending · unconfirmed</span><span class="v amt">${f(S.pending)}</span></div>
        <div class="kv"><span class="k">Total</span><span class="v amt">${f(S.total)} ${S.unit}</span></div>
      </div>
      <div class="panel"><div class="plabel">Activity</div><div id="vAct">${activity}</div></div>
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
  // Load real received-outputs into the Activity panel.
  (async () => {
    if (!IS_TAURI) return;
    const el = $("#vAct"); if (!el) return;
    try {
      const rows = await invoke("list_received");
      if (rows && rows.length){
        el.innerHTML = rows.slice(0, 8).map(r => `
          <div class="act">
            <div class="ai in">${I.down}</div>
            <div><div class="al">Received${r.spent?` <span class="atag">spent</span>`:""}</div><div class="am">block ${Number(r.height).toLocaleString()} · ${r.txOut}</div></div>
            <div><div class="av ${r.spent?"":"in"}"><span class="amt">+${Number(r.amount).toFixed(6)}</span></div><div class="at">${r.spent?"spent":"confirmed"}</div></div>
          </div>`).join("");
      } else {
        el.innerHTML = `<div class="at-empty" style="padding:28px 8px">${I.clock}<p>No received outputs yet. Incoming payments appear here once your wallet scans them.</p></div>`;
      }
    } catch(e){}
  })();
}

// ── Send ───────────────────────────────────────────────────────────
function showOut(el, kind, html){
  if (!el) return;
  el.style.display = "block"; el.innerHTML = html;
  el.style.color = kind==="err" ? "var(--red)" : kind==="ok" ? "var(--green)" : "var(--text-secondary)";
}
function send(){
  const forkLive = S.tip != null && S.tip >= FORK;
  return `
    <div class="pageh"><div class="h1">Send</div><div class="sub">${forkLive?"Private by default · hides amount &amp; recipient":"Transparent transfer · shielded sends unlock at h"+FORK.toLocaleString()}</div></div>
    <div class="panel" style="max-width:640px">
      <div class="plabel">Transfer</div>
      <div class="at-field"><div class="fl">Recipient address</div><input class="at-input" id="sAddr" placeholder="tCYNC… · standard, subaddress or integrated"></div>
      <div class="at-field"><div class="fl">Amount (${S.unit})</div><input class="at-input" id="sAmt" inputmode="decimal" placeholder="0.00"></div>
      <div class="at-field"><div class="fl">Memo — optional, encrypted to the recipient</div><input class="at-input" id="sMemo" placeholder="note…"></div>
      <div class="kv"><span class="k">Spendable</span><span class="v amt">${f(S.transparent)} ${S.unit}</span></div>
      <button class="cta" id="sSend" style="width:100%;margin-top:10px">Review &amp; send</button>
      <div class="note" id="sOut" style="margin-top:12px;display:none"></div>
    </div>
    <p class="note" style="margin-top:16px">Sends are built on device and submitted to your node. Double-check the address — transfers are irreversible.</p>
  `;
}
function wireSend(){
  const btn = $("#sSend"), out = $("#sOut");
  if (!btn) return;
  let confirming = false;
  btn.onclick = async () => {
    const addr = ($("#sAddr").value || "").trim();
    const amt = parseFloat($("#sAmt").value || "0");
    const memo = ($("#sMemo").value || "").trim();
    if (!addr){ showOut(out,"err","Enter a recipient address."); return; }
    if (!(amt > 0)){ showOut(out,"err","Enter a positive amount."); return; }
    if (amt > S.transparent + 1e-9){ showOut(out,"err",`Amount exceeds your spendable ${f(S.transparent)} ${S.unit}.`); return; }
    if (!confirming){
      confirming = true;
      btn.textContent = `Confirm — send ${amt} ${S.unit}`;
      showOut(out,"", `Sending <b>${amt} ${S.unit}</b> to <span class="mono" style="font-size:11px;word-break:break-all">${addr}</span>${memo?` · memo "${memo}"`:""}. Click again to confirm.`);
      return;
    }
    btn.disabled = true; btn.textContent = "Sending…";
    try {
      const txid = await invoke("send_transaction", { address: addr, amount: amt, memo: memo || null });
      showOut(out,"ok",`Sent ✓ — <span class="mono" style="font-size:11px;word-break:break-all">${txid}</span>`);
      $("#sAddr").value = ""; $("#sAmt").value = ""; $("#sMemo").value = "";
      pollWallet();
    } catch(e){
      showOut(out,"err", String((e && e.message) || e));
    }
    btn.disabled = false; btn.textContent = "Review & send"; confirming = false;
  };
  ["sAddr","sAmt","sMemo"].forEach(id => { const el = $("#"+id); if (el) el.oninput = () => { if (confirming){ confirming = false; btn.textContent = "Review & send"; if (out){ out.style.display="none"; } } }; });
}

// ── Receive ────────────────────────────────────────────────────────
function receive(){
  return `
    <div class="pageh"><div class="h1">Receive</div><div class="sub">Share an address to get paid · private by default</div></div>
    <section class="grid2">
      <div class="panel" style="text-align:center">
        <div class="plabel" style="text-align:left">Your address</div>
        <div id="rQr" style="display:flex;justify-content:center;align-items:center;min-height:160px;padding:14px 0;color:var(--text-tertiary)">generating…</div>
        <div id="rAddr" class="mono" style="font-size:11px;word-break:break-all;color:var(--text-secondary);margin:6px 4px 14px">loading…</div>
        <div class="at-actions" style="justify-content:center"><button class="cta" id="rCopy">Copy address</button></div>
      </div>
      <div class="panel">
        <div class="plabel">More addresses</div>
        <p class="note" style="margin-bottom:14px">A fresh <b>subaddress</b> is unlinkable — senders can't tell two of your addresses belong to one wallet. An <b>integrated address</b> embeds a payment ID for matching invoices.</p>
        <div style="display:flex;gap:10px;flex-wrap:wrap"><button class="ghost" id="rSub">New subaddress</button><button class="ghost" id="rInt">Integrated address</button></div>
        <div class="note" id="rMore" style="margin-top:16px;display:none"></div>
      </div>
    </section>
  `;
}
async function setReceiveAddr(addr){
  if (addr) S.address = addr;
  const a = $("#rAddr"); if (a) a.textContent = addr || "—";
  const q = $("#rQr");
  if (q && addr){
    try { const svg = await invoke("generate_qr_svg", { payload: addr }); q.innerHTML = `<div style="width:180px;height:180px;background:#fff;border-radius:8px;padding:8px;box-sizing:border-box">${svg}</div>`; }
    catch { q.textContent = "(QR unavailable)"; }
  }
}
function wireReceive(){
  (async () => {
    let addr = S.address;
    if (!addr){ try { addr = await invoke("get_wallet_address"); } catch{} }
    await setReceiveAddr(addr);
  })();
  const copy = $("#rCopy"); if (copy) copy.onclick = async () => { try{ await navigator.clipboard.writeText(S.address||""); }catch{} copy.textContent="Copied ✓"; setTimeout(()=>copy.textContent="Copy address",1400); };
  const showMore = (label, addr) => { const m = $("#rMore"); if (!m) return; m.style.display="block"; m.style.color="var(--text-secondary)"; m.innerHTML = `${label}:<br><span class="mono" style="font-size:11px;word-break:break-all;color:var(--gold-200)">${addr}</span>`; };
  const errMore = (e) => { const m = $("#rMore"); if (!m) return; m.style.display="block"; m.style.color="var(--red)"; m.textContent = String((e && e.message) || e); };
  const sub = $("#rSub"); if (sub) sub.onclick = async () => { sub.disabled=true; try{ const a = await invoke("new_subaddress"); showMore("New subaddress", a); await setReceiveAddr(a); }catch(e){ errMore(e); } sub.disabled=false; };
  const int = $("#rInt"); if (int) int.onclick = async () => { int.disabled=true; try{ const a = await invoke("integrated_address"); showMore("Integrated address", a); await setReceiveAddr(a); }catch(e){ errMore(e); } int.disabled=false; };
}

// ── Shield / Unshield (Spark pool · activates at h29000) ────────────
let shDir = "shield"; // "shield" (transparent→pool) | "unshield" (pool→transparent)
function shield(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const toFork = S.tip == null ? null : Math.max(0, FORK - S.tip);
  const isShield = shDir === "shield";
  const srcLabel = isShield ? "Transparent" : "Shielded";
  const srcBal = isShield ? S.transparent : S.shielded;
  const gate = !forkLive
    ? `<div class="nudge" style="margin-bottom:18px"><div class="ni">${I.clock}</div>
         <div class="nt">The shielded pool activates at <b>h${FORK.toLocaleString()}</b>${toFork!=null?` — <b class="amt">~${toFork.toLocaleString()}</b> blocks away`:""}. Shield &amp; unshield unlock then.</div></div>`
    : "";
  return `
    <div class="pageh"><div class="h1">Shield</div><div class="sub">Move value between your transparent balance and the private Spark pool</div></div>
    ${gate}
    <div class="at-types">
      <button class="at-type ${isShield?"on":""}" data-sh="shield"><div class="tt">${I.shieldPlain} Shield</div><div class="ts">Transparent → pool · join the anonymity set.</div></button>
      <button class="at-type ${!isShield?"on":""}" data-sh="unshield"><div class="tt">${I.unshield} Unshield</div><div class="ts">Pool → transparent · your clean public exit.</div></button>
    </div>
    <div class="panel" style="max-width:640px;margin-top:16px">
      <div class="plabel">${isShield?"Shield into the pool":"Unshield to transparent"}</div>
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
      ${step(3,"Exit","Send the clean transparent coins to your exchange or custodian. Their chain analysis sees a normal transparent transfer.",sendBtn)}
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
    if (amt > srcBal + 1e-9){ showOut(out,"err",`Amount exceeds your ${isShield?"transparent":"shielded"} ${f(srcBal)} ${S.unit}.`); return; }
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
      <div class="tile"><div class="tk">Hashrate</div><div class="tv"><span id="mHash">${hps(m.hashrate)}</span> <span style="font-size:13px;color:var(--text-tertiary)">H/s</span></div><div class="td" id="mHashSub">${running?(m.hashrate>0?"live":"building dataset…"):"—"}</div></div>
      ${third}
      <div class="tile"><div class="tk">Threads</div><div class="tv" id="mThreadsTv">${running?m.threads:want}</div><div class="td">of ${maxT} cores</div></div>
    </div>
    <div class="panel"><div class="plabel">Smart mining advisor</div>
      <div class="kv"><span class="k">Your hashrate</span><span class="v"><span id="mHash2">${hps(m.hashrate)}</span> H/s</span></div>
      <div class="kv"><span class="k">Network hashrate</span><span class="v" id="mNet">${m.netHashrate?hps(m.netHashrate)+" H/s":"—"}</span></div>
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
      <div class="kv"><span class="k">Payout</span><span class="v">${mode==='pool'?'pool-decided · to your login address':'your wallet · transparent'}</span></div>
      <div style="margin-top:16px"><button class="cta" id="mToggle" ${(!running&&!canMine)?"disabled":""}>${running?"Stop mining":"Start mining"}</button></div>
      ${(!running&&!canMine)?`<div class="note" style="margin-top:12px">Waiting for the node to be reachable…</div>`:""}
      <div class="note" id="mErr" style="margin-top:12px;color:var(--red);display:none"></div>
    </div>
    <p class="note" style="margin-top:16px">Mining runs the native rig as a separate process — nothing hashes in this window. <b>Solo</b> pays you the whole block when you win; <b>Pool</b> earns steady shares so small miners still get paid; <b>Auto</b> measures your hashrate and routes you to whichever actually pays. Rewards are transparent — Shield them after the h${FORK.toLocaleString()} fork.</p>
  `;
}
let miningTimer = null;
function patchMining(){
  const m = S.mining;
  const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  set("mStatus", m.mining?"Mining":"Idle");
  const sub = document.getElementById("mStatusSub"); if (sub){ sub.textContent = m.mining?(m.mode==="pool"?"pool":"solo"):"stopped"; sub.className = "td "+(m.mining?"g":""); }
  set("mHash", hps(m.hashrate)); set("mHash2", hps(m.hashrate));
  set("mHashSub", m.mining?(m.hashrate>0?"live":"building dataset…"):"—");
  const poolRunning = m.mining && m.mode==="pool";
  set("mThird", poolRunning ? (m.sharesAccepted||0) : (m.blocksFound||0));
  const tsub = document.getElementById("mThirdSub"); if (tsub) tsub.textContent = poolRunning ? `accepted${m.sharesRejected?` · ${m.sharesRejected} rej`:""}` : "this run";
  set("mNet", m.netHashrate?hps(m.netHashrate)+" H/s":"—");
  set("mDiff", m.difficulty?num(Math.round(m.difficulty)):"—");
  set("mEst", dur(m.estSoloSecs));
  const rec = recLabel(m); const re = document.getElementById("mRec"); if (re){ re.textContent = rec.t; re.className = "v "+rec.cls; }
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
        const st = await invoke("start_mining", { threads:S.minerThreads, mode:"pool", pool_url:S.poolUrl });
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
      else { S.autoRouted = false; st = await invoke("start_mining", { threads:S.minerThreads, mode:backendMode, pool_url:poolUrl }); }
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
      </div>
      <div style="margin-top:18px;display:flex;gap:10px">
        <button class="cta" id="nStart" ${canStart?"":"disabled"} style="${running?"display:none":""}">Start node</button>
        <button class="ghost" id="nStop" ${canStop?"":"disabled"} style="${running&&canStop?"":"display:none"}">Stop node</button>
      </div>
      ${(!n.binAvailable)?`<div class="note" style="margin-top:12px">The node binary isn't bundled with this build.</div>`:""}
      ${(running&&!canStop)?`<div class="note" style="margin-top:12px">This node is running outside CyncHub, so CyncHub won't stop it.</div>`:""}
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
  // flip controls without a full re-render unless running-state changed
  const start = document.getElementById("nStart"), stop = document.getElementById("nStop");
  if (start) start.style.display = running?"none":"";
  if (stop) stop.style.display = (running&&n.managed)?"":"none";
}
async function refreshNodes(){
  try { const st = await invoke("node_status"); if (st) S.node = st; } catch(e){}
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
function diagnostics(){
  return `
    <div class="pageh"><div class="h1">Diagnostics</div><div class="sub">Health checks · for support &amp; audit</div></div>
    <div class="panel"><div class="plabel">Self-check</div>
      <div class="kv"><span class="k">Node reachable</span><span class="v ${S.connected?"g":""}">${S.connected?"yes":"no"}</span></div>
      <div class="kv"><span class="k">Node tip</span><span class="v">${num(S.tip)}</span></div>
      <div class="kv"><span class="k">Wallet scanned to</span><span class="v">${S.scanned?num(S.scannedHeight):"—"}</span></div>
      <div class="kv"><span class="k">UTXOs tracked</span><span class="v">${S.scanned?num(S.utxoCount):"—"}</span></div>
      <div class="kv"><span class="k">Consensus network</span><span class="v">${S.network||"—"}</span></div>
    </div>
    <p class="note" style="margin-top:16px">Surfaces the CYNC-* self-checks + gated-surface registry for support and audit.</p>
  `;
}
function settings(){
  const forkLive = S.tip != null && S.tip >= FORK;
  const theme = getTheme();
  const lk = getAutoLock();
  const lkTxt = lk === 0 ? "Off" : lk >= 60 ? (lk/60)+" h" : lk+" min";
  return `
    <div class="pageh"><div class="h1">Settings</div><div class="sub">CyncHub · on the CoinCync network</div></div>
    <div class="panel"><div class="plabel">Appearance</div>
      <div class="kv" style="align-items:flex-start"><span class="k">Theme</span>
        <span class="v" style="display:flex;gap:7px;flex-wrap:wrap;justify-content:flex-end;max-width:360px">
          ${THEMES.map(t => `<button class="seg ${theme===t.id?'on':''}" data-theme-set="${t.id}">${t.label}</button>`).join("")}
        </span></div>
    </div>
    <div class="panel" style="margin-top:16px"><div class="plabel">Security</div>
      <div class="kv"><span class="k">Session</span><span class="v g">unlocked</span></div>
      <div class="kv"><span class="k">Auto-lock when idle</span>
        <span class="v" style="display:flex;gap:6px;flex-wrap:wrap">
          ${[["Off",0],["5 min",5],["15 min",15],["30 min",30],["1 h",60]].map(([t,v])=>`<button class="seg ${lk===v?'on':''}" data-lock-set="${v}">${t}</button>`).join("")}
        </span></div>
      <div class="kv"><span class="k">Current</span><span class="v">${lkTxt}</span></div>
      <div style="margin-top:14px"><button class="ghost" id="lockBtn">Lock now</button></div>
    </div>
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
  view.querySelectorAll("[data-theme-set]").forEach(b => b.onclick = () => { setTheme(b.dataset.themeSet); render("settings"); });
  view.querySelectorAll("[data-lock-set]").forEach(b => b.onclick = () => { setAutoLock(parseInt(b.dataset.lockSet,10)||0); render("settings"); });
  const ct = $("#chToggle"), cerr = $("#chErr");
  if (ct) ct.onclick = async () => {
    if (cerr){ cerr.style.display="none"; cerr.textContent=""; }
    ct.disabled = true; ct.textContent = S.churnOn ? "Stopping…" : "Starting…";
    try { const st = await invoke(S.churnOn?"stop_churn":"start_churn"); S.churnOn = !!(st && st.running); render("settings"); }
    catch(e){ if (cerr){ cerr.textContent = String((e&&e.message)||e); cerr.style.display="block"; } ct.disabled=false; ct.textContent = S.churnOn?"Stop":"Start"; }
  };
}

// ── router ─────────────────────────────────────────────────────────
const SCREENS = { vault, send, receive, shield, lens, attest, swap, mining, nodes, diagnostics, settings };
function render(name){
  current = name;
  const fn = SCREENS[name] || vault;
  view.innerHTML = fn();
  document.querySelectorAll(".nav").forEach(n => n.classList.toggle("active", n.dataset.screen === name));
  if (name !== "mining") stopMiningPoll();
  if (name !== "nodes") stopNodesPoll();
  if (name === "vault") wireVault();
  if (name === "send") wireSend();
  if (name === "receive") wireReceive();
  if (name === "shield") wireShield();
  if (name === "attest") wireAttest();
  if (name === "mining") wireMining();
  if (name === "nodes") wireNodes();
  if (name === "settings") wireSettings();
  // in-content links that navigate (e.g. Vault's Attest card)
  view.querySelectorAll("[data-screen]").forEach(el => el.onclick = () => render(el.dataset.screen));
}
document.querySelectorAll(".nav[data-screen]").forEach(n => n.onclick = () => render(n.dataset.screen));

// ── auth gate: unlock / create / restore (desktop app only) ─────────
const authEl = (() => { const d = document.createElement("div"); d.className = "auth"; d.style.display = "none"; document.body.appendChild(d); return d; })();
const authLogo = `<div class="auth-logo">C</div>`;
function aerr(m){ const e = document.getElementById("aerr"); if (e) e.textContent = m || ""; }
function showAuth(mode, data){ authEl.style.display = "grid"; authEl.innerHTML = authHtml(mode, data); wireAuth(mode); const i = authEl.querySelector("input,textarea"); if (i) i.focus(); }
function hideAuth(){ authEl.style.display = "none"; authEl.innerHTML = ""; }

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
  if (mode === "seed") return `<div class="auth-card">${authLogo}<div class="auth-title">Your recovery phrase</div>
    <div class="auth-warn">Write these words down and keep them safe. They are the ONLY way to recover your wallet — CyncHub cannot reset it.</div>
    <div class="auth-seed">${data || "(seed unavailable)"}</div>
    <button class="auth-btn" id="adone">I've written it down</button></div>`;
  return "";
}

function wireAuth(mode){
  if (mode === "unlock"){
    const go = async () => { const pw = document.getElementById("apw").value; if (!pw){ aerr("enter your password"); return; }
      aerr(""); try { await invoke("unlock_wallet", { password: pw }); enterApp(); } catch(e){ aerr("invalid password"); } };
    document.getElementById("abtn").onclick = go;
    document.getElementById("apw").onkeydown = e => { if (e.key === "Enter") go(); };
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
    document.getElementById("adone").onclick = () => enterApp();
  }
}

function lockApp(){ if (pollTimer){ clearInterval(pollTimer); pollTimer = null; } stopMiningPoll(); stopNodesPoll(); if (idleTimer){ clearTimeout(idleTimer); idleTimer = null; } document.body.dataset.locked = "1"; invoke("lock_wallet").catch(()=>{}); S.scanned=false; S.total=S.transparent=S.shielded=0; document.body.classList.remove("reveal"); showAuth("unlock"); }

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
}

let pollTimer = null;
function startPolling(){
  if (pollTimer) return;
  pollTimer = setInterval(async () => {
    await pollChain();
    // only re-render the live network screens so we don't disturb inputs
    if (["lens","nodes","diagnostics","vault","settings"].includes(current)) render(current);
  }, 5000);
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
