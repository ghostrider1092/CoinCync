// ── CONFIG ────────────────────────────────────────────────────
// ── Network selection ─────────────────────────────────────────
//
// `RPC` and `REST` are intentionally `let` (not const) so the
// network toggle in the nav can swap them at runtime. The active
// network is persisted in localStorage('cync-net') and restored
// on page load. See setNetwork() below.
//
// Path layout (matches deploy/explorer/Caddyfile):
//   POST /api/testnet      → testnet coincync-node JSON-RPC (port 28081)
//   POST /api/mainnet      → mainnet coincync-node JSON-RPC (port 19081, post-launch)
//   GET  /api/v1/testnet/* → testnet REST API (rpc/rest.rs)
//   GET  /api/v1/mainnet/* → mainnet REST API (post-launch)
//
// Mainnet pre-launch: rpc() short-circuits and returns null with a
// flag so callers stay quiet, while the launch-countdown banner
// (rendered above the page) keeps ticking.

// Fort-Knox item 4: IPFS-mirror portability.
//
// The explorer is intended to be pinnable to IPFS as a fallback if
// `explorer.coincync.network` becomes unreachable. On the canonical
// deploy, `/api/*` is nginx-proxied to the local coincync-node — so
// origin-relative URLs work. On an IPFS gateway (e.g.
// `https://cloudflare-ipfs.com/ipfs/<cid>/`) there is no such proxy
// and origin-relative URLs would 404. `_computeApiBase()` picks the
// right base URL for the current context:
//
//   1. `?api=<url>` query param — highest priority; power-user
//      escape hatch, useful for pointing the mirror at a personal
//      coincync-node.
//   2. `localStorage['cync-api-base']` — persisted user preference.
//   3. Origin-relative (empty string) — the canonical deploys
//      (`explorer.coincync.network`, `localhost`, `127.0.0.1`).
//   4. Canonical API host — everything else, i.e. any IPFS gateway,
//      any mirror. Assumes CORS is enabled on api.coincync.network
//      (verified by the Fort-Knox item 4 rollout runbook before
//      publishing an IPFS pin).
//
// Trailing slashes are trimmed so we never emit `.../api/testnet`
// twice.
function _computeApiBase() {
  try {
    const q = new URLSearchParams(window.location.search).get('api');
    if (q) return q.replace(/\/+$/, '');
  } catch (_) { /* older browsers or file:// — fall through */ }
  try {
    const ls = localStorage.getItem('cync-api-base');
    if (ls) return ls.replace(/\/+$/, '');
  } catch (_) { /* private-mode / storage-blocked — fall through */ }
  const h = (typeof window !== 'undefined' && window.location) ? window.location.hostname : '';
  if (h === 'explorer.coincync.network' || h === 'localhost' || h === '127.0.0.1' || h === '') {
    return '';
  }
  return 'https://api.coincync.network';
}
const _API_BASE = _computeApiBase();

let _activeNetwork = (localStorage.getItem('cync-net') === 'mainnet') ? 'mainnet' : 'testnet';
let RPC  = _API_BASE + '/api/' + _activeNetwork;
let REST = _API_BASE + '/api/v1/' + _activeNetwork;

// Mainnet launch is hardcoded in src/mainnet.rs as Unix timestamp
// 1790812800 (October 1, 2026 00:00:00 UTC). Until then the explorer
// renders a countdown instead of polling the (nonexistent) mainnet
// backend.
const MAINNET_LAUNCH_UNIX = 1790812800;
function isMainnetLaunched() {
  return Math.floor(Date.now() / 1000) >= MAINNET_LAUNCH_UNIX;
}

// Switch the active network. Called by the nav toggle buttons.
// Updates state, persists to localStorage, repaints the toggle UI,
// shows/hides the pre-launch countdown banner, and triggers an
// immediate re-poll so the new network's data lands within one
// frame of the click.
function setNetwork(net) {
  if (net !== 'testnet' && net !== 'mainnet') return;
  _activeNetwork = net;
  localStorage.setItem('cync-net', net);
  _blocksGenesisBackfillGen++;
  // Same base-URL rule as page-load. `_API_BASE` is picked once at
  // load and doesn't change with the network toggle — it's a
  // deploy-topology property (same-origin vs. IPFS mirror), not a
  // network property.
  RPC  = _API_BASE + '/api/' + net;
  REST = _API_BASE + '/api/v1/' + net;

  // Repaint the toggle: the active button gets the colored pill,
  // and mainnet gets a different shade post-launch vs pre-launch
  // so users can visually tell whether the chain is live yet.
  const tn = document.getElementById('net-btn-testnet');
  const mn = document.getElementById('net-btn-mainnet');
  if (tn && mn) {
    tn.classList.toggle('active', net === 'testnet');
    mn.classList.toggle('active', net === 'mainnet');
    mn.classList.toggle('mainnet-active', net === 'mainnet' && isMainnetLaunched());
    mn.classList.toggle('pre-launch', !isMainnetLaunched());
    mn.title = isMainnetLaunched()
      ? 'Mainnet — live'
      : 'Mainnet launches October 1, 2026 00:00:00 UTC';
  }

  // Show/hide the launch countdown banner.
  const banner = document.getElementById('mainnet-countdown-banner');
  if (banner) {
    banner.style.display = (net === 'mainnet' && !isMainnetLaunched()) ? 'block' : 'none';
  }

  // If we're already polling, kick a fresh fetch so the user
  // sees the new network's data immediately rather than waiting
  // for the next interval tick. Wrapped in a try/catch because
  // the poller may not have been initialized yet on first paint.
  try { if (typeof refreshAll === 'function') refreshAll(); } catch (e) {}
}

// Format the time remaining until mainnet launch as
// "Nd Hh Mm Ss". Used by the countdown ticker.
function _fmtMainnetCountdown() {
  const now = Math.floor(Date.now() / 1000);
  let remaining = MAINNET_LAUNCH_UNIX - now;
  if (remaining <= 0) return 'now';
  const d = Math.floor(remaining / 86400); remaining -= d * 86400;
  const h = Math.floor(remaining / 3600);  remaining -= h * 3600;
  const m = Math.floor(remaining / 60);    remaining -= m * 60;
  return d + 'd ' + h + 'h ' + m + 'm ' + remaining + 's';
}

// Tick the countdown banner every second. Cheap (DOM write only).
// When mainnet launches, the banner disappears and the toggle's
// "pre-launch" state automatically flips on the next setNetwork()
// call (or on the next page load, which is more common).
setInterval(function() {
  const el = document.getElementById('mainnet-countdown-value');
  if (el) el.textContent = _fmtMainnetCountdown();
  // Auto-hide the banner the moment mainnet goes live, even
  // mid-session, so a long-open browser tab doesn't keep showing
  // a stale "launching in 0s" header.
  if (isMainnetLaunched()) {
    const banner = document.getElementById('mainnet-countdown-banner');
    if (banner && banner.style.display !== 'none') banner.style.display = 'none';
  }
}, 1000);

// Initialize the toggle to match restored state on first paint.
// (Called immediately so the visual matches localStorage before
// any user interaction.)
document.addEventListener('DOMContentLoaded', function() {
  applyExplorerMode();
  setNetwork(_activeNetwork);
  // Restore last visited page
  var savedPage = localStorage.getItem('cync-page');
  if (savedPage && PAGES.includes(savedPage)) go(savedPage);
  // First-load init for the home-tab constellation. (go() handles
  // re-navigation to home, but the page-home div starts active so the
  // routing function is never called on initial paint.) Defer 300 ms so
  // the rest of the boot sequence — RPC keys, network restore, layout —
  // finishes before three.js starts allocating GPU buffers.
  if (!savedPage || savedPage === 'home') {
    setTimeout(function(){
      if (typeof initConstellation === 'function') {
        try { initConstellation(); } catch(_){}
      }
    }, 300);
    // v1.0.10 status panel: kick on initial paint too. Same reason as
    // initConstellation above — go() isn't called on first load when
    // page-home starts active in the DOM.
    setTimeout(function(){
      if (typeof ensureV108Polling === 'function') {
        try { ensureV108Polling(); } catch(_){}
      }
    }, 400);
  }
});
// _rpc: internal RPC endpoint for health queries. Never displayed to users.
// proxy: nginx proxy path (production). _rpc: direct fallback (local dev / offline).
// Fleet topology — kept in sync with scripts/fleet-config.json.
// `loopbackRpc` flag: hosts that bind coincync-node RPC to 127.0.0.1
// (per fleet-config.json rpc_bind) can't be probed directly from the
// explorer box. The Health page shows them with an amber "Protected
// (loopback-only)" badge — intentional, not a problem.
// `apiNginxOnly` flag: api host runs nginx only (no coincync-node);
// probing it would always 504. Shown for topology completeness only.
const NODES=[
  {id:'1a2b',label:'seed1',   loc:'Vultr · public bind',     role:'Seed · public RPC',         proxy:'/health/seed1',    _rpc:'http://216.128.156.239:28081'},
  {id:'3c4d',label:'seed2',   loc:'Vultr',                   role:'Seed · public RPC',         proxy:'/health/seed2',    _rpc:'http://140.82.57.168:28081'},
  {id:'5e6f',label:'seed3',   loc:'Vultr · loopback RPC',    role:'Seed · loopback-only',      proxy:'/health/seed3',    _rpc:'http://45.32.251.6:28081',    loopbackRpc:true},
  {id:'7a8b',label:'explorer',loc:'Vultr · loopback RPC',    role:'Explorer · loopback-only',  proxy:'/health/explorer', _rpc:'http://127.0.0.1:28081'},
  {id:'9c0d',label:'api',     loc:'Vultr · nginx-only',      role:'Public API · nginx gateway',proxy:'/health/api',      _rpc:'http://95.179.165.225:28081', apiNginxOnly:true},
  {id:'rxa1',label:'randomx', loc:'Vultr · loopback RPC',    role:'Miner · loopback-only',     proxy:'/health/randomx',  _rpc:'http://173.199.93.21:28081',  loopbackRpc:true},
  {id:'rxa2',label:'randomx2',loc:'Vultr · loopback RPC',    role:'Miner · loopback-only',     proxy:'/health/randomx2', _rpc:'http://45.32.79.234:28081',   loopbackRpc:true},
  {id:'rly1',label:'relay1',  loc:'Vultr · loopback RPC',    role:'Relay · loopback-only',     proxy:'/health/relay1',   _rpc:'http://208.85.17.18:28081',   loopbackRpc:true},
  {id:'rly2',label:'relay2',  loc:'Vultr · loopback RPC',    role:'Relay · loopback-only',     proxy:'/health/relay2',   _rpc:'http://70.34.250.31:28081',   loopbackRpc:true},
];
const $=id=>document.getElementById(id);
const num=n=>Number(n).toLocaleString();
function atomicToCyncDisplayNumber(value){
  // Keep six display decimals using integer arithmetic before converting to
  // Number; aggregate RPC fields are decimal strings because they exceed u64.
  return Number(BigInt(value??0)/1000000n)/1000000;
}
const age=ts=>{const s=Math.max(0,Math.floor(Date.now()/1000)-ts);return s<60?s+'s':s<3600?Math.floor(s/60)+'m':s<86400?Math.floor(s/3600)+'h':Math.floor(s/86400)+'d';};
const fmtTs=ts=>new Date(ts*1000).toUTCString();
const fmtSize=b=>b>1024?(b/1024).toFixed(1)+' kB':b+' B';
const IS_LOCALHOST = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
const allow_remote_crypto = new URLSearchParams(window.location.search).get('allow_remote_crypto') === '1';
const enable_browser_wallet = new URLSearchParams(window.location.search).get('enable_browser_wallet') === '1';
const EXPLORER_ALLOW_EXTERNAL_DEPS=(
  IS_LOCALHOST &&
  new URLSearchParams(window.location.search).get('allow_external_deps')==='1'
);
const SCRIPT_URLS = {
  d3: '/static/vendor/d3/7/d3.min.js',
  topojson: '/static/vendor/topojson-client/3/topojson-client.min.js',
  globe: '/static/vendor/globe.gl/2.27.3/globe.gl.min.js',
};
const _scriptLoadCache = {};
function ensureScriptLoaded(url, globalName) {
  const isExternal = /^https?:\/\//i.test(url);
  if (isExternal && !EXPLORER_ALLOW_EXTERNAL_DEPS) {
    return Promise.reject(new Error('External explorer dependencies are disabled'));
  }
  if (globalName && typeof window[globalName] !== 'undefined') return Promise.resolve();
  if (_scriptLoadCache[url]) return _scriptLoadCache[url];
  _scriptLoadCache[url] = new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = url;
    s.async = true;
    s.onload = () => resolve();
    s.onerror = () => reject(new Error('Failed to load script: ' + url));
    document.head.appendChild(s);
  });
  return _scriptLoadCache[url];
}
async function ensureNetworkVizDeps() {
  await ensureScriptLoaded(SCRIPT_URLS.d3, 'd3');
  await ensureScriptLoaded(SCRIPT_URLS.topojson, 'topojson');
  await ensureScriptLoaded(SCRIPT_URLS.globe, 'Globe');
}
// CoinCync 1.0 is RandomX-only — see `consensus::pow::PowAlgorithm`.
// The pre-1.0 multi-algorithm rotation (Yescrypt-heavy / Yescrypt-light)
// was removed in the trim. Any non-zero algorithm id here is either a
// future-version block we can't describe or a bug feeding the explorer
// — render "unknown" rather than silently falling back to RandomX, so
// the bug is visible.
const algos=['RandomX'];
const algoName=n=>algos[n]||'unknown';
const fmtHr=h=>{if(h>1e9)return(h/1e9).toFixed(2)+' GH/s';if(h>1e6)return(h/1e6).toFixed(2)+' MH/s';if(h>1e3)return(h/1e3).toFixed(2)+' KH/s';return h.toFixed(0)+' H/s';};
const _rpcKeyFromQuery = new URLSearchParams(window.location.search).get('rpc_key');
if (_rpcKeyFromQuery) localStorage.setItem('COINCYNC_RPC_API_KEY', _rpcKeyFromQuery);
function _getRpcAuthKey() {
  const fromWindow = typeof window.COINCYNC_RPC_API_KEY === 'string' ? window.COINCYNC_RPC_API_KEY : '';
  const fromStorage = localStorage.getItem('COINCYNC_RPC_API_KEY') || '';
  return (fromWindow || fromStorage || '').trim();
}
function _rpcRequestOpts(body) {
  const headers = {'Content-Type':'application/json'};
  const authKey = _getRpcAuthKey();
  if (authKey) headers.Authorization = 'Bearer ' + authKey;
  return {method:'POST',headers,body};
}

// ── ANIMATED COUNTER ──────────────────────────────────────────
function animateValue(el, start, end, duration=800) {
  if (!el || start === end) { if(el) el.textContent = num(end); return; }
  const range = end - start;
  const startTime = performance.now();
  function tick(now) {
    const elapsed = now - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
    const current = Math.round(start + range * eased);
    el.textContent = num(current);
    if (progress < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

// ── BLOCK PULSE ──────────────────────────────────────────────
let _lastPulseHeight = 0;
function blockPulse(height) {
  if (height <= _lastPulseHeight) return;
  _lastPulseHeight = height;
  const bar = document.getElementById('block-pulse-bar');
  if (!bar) return;
  bar.style.animation = 'none';
  bar.offsetHeight; // force reflow
  bar.style.animation = 'blockRipple 1.2s ease-out forwards';
}

// ── STATE ─────────────────────────────────────────────────────
let chainHeight=0,chainDiff=0,blockList=[],loadedHeight=0,diffChart=null,miningChart=null;
let _lastInfo = null;
let _lastPollAtMs = 0;
let _lastChainHeightSeen = 0;
let _apiHealthProbeCountdown = 0;
const _operatorAlerts = [];
// Cancels in-flight "load entire chain" backfill when switching network or re-navigating.
let _blocksGenesisBackfillGen = 0;
let _blocksGenesisBackfillRunning = false;
function _yieldToUi(){return new Promise(r=>requestAnimationFrame(()=>r()));}

function _pushOperatorAlert(level, message){
  const ts = new Date().toLocaleTimeString();
  _operatorAlerts.unshift({ level, message, ts });
  if(_operatorAlerts.length > 3) _operatorAlerts.pop();
  const el = $('ops-alert-feed');
  if(!el) return;
  el.innerHTML = _operatorAlerts.map(a=>{
    const c = a.level==='crit' ? '#EF4444' : a.level==='warn' ? '#F59E0B' : '#D4A059';
    return `<div><span style="color:${c}"></span> ${a.ts} — ${a.message}</div>`;
  }).join('');
}

function _updateOperatorStrip(info){
  const tipAge = info.tip_age_secs || 0;
  const peers = info.peer_count || 0;
  const dot = $('ops-fresh-dot');
  const color = tipAge <= 90 ? '#7EB87C' : tipAge <= 300 ? '#F59E0B' : '#EF4444';
  if(dot) dot.style.background = color;
  const h = $('ops-height'); if(h) h.textContent = '#'+num(info.height||0);
  const t = $('ops-tip-age'); if(t) t.textContent = tipAge+'s';
  const p = $('ops-peers'); if(p) p.textContent = String(peers);
  const r = $('ops-rpc-source'); if(r) r.textContent = RPC;
}

async function _probeApiHealth(){
  const label = $('ops-api-health');
  const t0 = performance.now();
  try{
    const body = JSON.stringify({jsonrpc:'2.0',id:1,method:'get_info',params:[]});
    const res = await fetch(RPC, _rpcRequestOpts(body));
    const ms = Math.round(performance.now() - t0);
    if(label) label.innerHTML = res.ok ? `<span style="color:#7EB87C">ok</span> ${ms}ms` : `<span style="color:#EF4444">http ${res.status}</span>`;
  }catch(_){
    if(label) label.innerHTML = `<span style="color:#EF4444">down</span>`;
  }
}

// ── RPC ───────────────────────────────────────────────────────
//
// Short-circuits to null when the active network is mainnet AND
// mainnet hasn't launched yet (per MAINNET_LAUNCH_UNIX above).
// This means: pages that select mainnet pre-launch see all the
// usual "—" placeholders instead of a flood of fetch errors in
// the console, while the launch-countdown banner keeps ticking
// at the top of the page.
// Top-explorer posture (Etherscan/Esplora style):
// UI talks to ONE backend API surface only. No client-side direct-node fallback.
// If backend is down/misconfigured, fail closed (null) so operators fix upstream wiring.
async function rpc(method,params=[]){
  if (_activeNetwork === 'mainnet' && !isMainnetLaunched()) return null;
  const body=JSON.stringify({jsonrpc:'2.0',id:1,method,params});
  const opts=_rpcRequestOpts(body);
  try{
    const r = await fetch(RPC,opts);
    if (!r.ok) return null;
    const j = await r.json();
    if (j && j.result !== undefined) return j.result;
  }catch(e){}
  return null;
}
async function rest(path){
  if (_activeNetwork === 'mainnet' && !isMainnetLaunched()) return null;
  try{const r=await fetch(REST+path);return r.json();}catch(e){return null;}
}



// ── RPC failure counter ──────────────────────────────────────
let _rpcFailures = 0;

function _updateDecayClock(tipAgeSecs){
  const el = $('decay-clock');
  const v = $('dc-val');
  if(!el || !v) return;
  // Format: 4m 32s
  const m = Math.floor(tipAgeSecs/60), s = tipAgeSecs%60;
  v.textContent = m>0 ? `${m}m ${s}s` : `${s}s`;
  // Color thresholds anchored to the 30s target block time. Natural variance
  // on a low-hashrate testnet can hit 3-5 block times without anything being
  // wrong, so warn starts at 6 block times. Crit at 14; dead at 30.
  el.classList.remove('decay-warn','decay-crit','decay-dead');
  if(tipAgeSecs >= 900)      el.classList.add('decay-dead');
  else if(tipAgeSecs >= 420) el.classList.add('decay-crit');
  else if(tipAgeSecs >= 180) el.classList.add('decay-warn');
}

function _ecgPush(buf, val){
  buf.push(val);
  if(buf.length>30) buf.shift();
}
function _ecgRender(elId, buf, deadVal=0){
  const el = $(elId);
  if(!el || buf.length===0) return;
  const max = Math.max(1, ...buf);
  const points = buf.map((v,i) => {
    const x = (i/Math.max(1,buf.length-1))*80;
    const y = 9 - (v/max)*7;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  }).join(' ');
  el.setAttribute('points', points || `0,9 80,9`);
}

function _heartbeat(){
  const el = $('net-heartbeat');
  if(!el) return;
  el.classList.add('beating');
  setTimeout(()=>el.classList.remove('beating'), 1200);
}
