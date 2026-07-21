// ── 3D GLOBE ─────────────────────────────────────────────────
// ── NODE REGISTRY ────────────────────────────────────────────────────────────
// `online`    – current live status (flipped by the health poll loop)
// `wasOnline` – previous state, used to detect reconnect events
// `height`    – last known block height (shown in tooltip)
// `failCount` – consecutive poll failures before we mark offline
const GNODES = [
  {label:'seed1',   id:'1a2b', lat:40.74, lng:-74.17, role:'Seed (US-East)',       city:'New Jersey, USA',     online:true, wasOnline:true, height:0, failCount:0, proxy:'/health/seed1',   _rpc:'http://66.135.23.193:28081'},
  {label:'seed2',   id:'3c4d', lat:52.37, lng:4.90,   role:'Seed (Europe)',        city:'Amsterdam, NL',       online:true, wasOnline:true, height:0, failCount:0, proxy:'/health/seed2',   _rpc:'http://140.82.57.168:28081'},
  {label:'seed3',   id:'5e6f', lat:35.68, lng:139.69, role:'Seed (Asia-Pacific)',  city:'Tokyo, Japan',        online:true, wasOnline:true, height:0, failCount:0, proxy:'/health/seed3',   _rpc:'http://207.148.111.76:28081'},
  {label:'explorer',id:'7a8b', lat:32.78, lng:-96.80, role:'Explorer + Relay',     city:'Dallas, USA',         online:true, wasOnline:true, height:0, failCount:0, proxy:'/health/explorer',_rpc:'http://207.148.6.50:28081'},
  {label:'api',     id:'9c0d', lat:50.11, lng:8.68,   role:'Public API + Relay',   city:'Frankfurt, Germany',  online:true, wasOnline:true, height:0, failCount:0, proxy:'/health/api',     _rpc:'http://95.179.165.225:28081'},
];

// How many consecutive failures before a node is considered offline
const FAIL_THRESHOLD = 2;
// How often to poll each node (ms)
const NODE_POLL_MS   = 12000;
// How long reconnect-pulse arcs stay visible (ms)
const PULSE_DURATION = 2200;

// ── ARC BUILDERS ─────────────────────────────────────────────────────────────

// Returns arcs only between pairs of nodes that are BOTH online.
function buildLiveArcs(extraPulse=[]) {
  const live = GNODES.filter(n => n.online);
  const arcs = [];
  live.forEach((a, i) => live.forEach((b, j) => {
    if (j > i) arcs.push({
      startLat: a.lat, startLng: a.lng,
      endLat:   b.lat, endLng:   b.lng,
      pulse: false,
    });
  }));
  return [...arcs, ...extraPulse];
}

// Fires a bright burst of arcs FROM a node that just reconnected to all live peers.
function _fireReconnectPulse(node) {
  if (!_globe) return;
  const peers = GNODES.filter(n => n.online && n.label !== node.label);
  if (!peers.length) return;
  const pulses = peers.map(n => ({
    startLat: node.lat, startLng: node.lng,
    endLat:   n.lat,   endLng:   n.lng,
    pulse: true,
  }));
  _globe.arcsData(buildLiveArcs(pulses));
  setTimeout(() => { if (_globe) _globe.arcsData(buildLiveArcs()); }, PULSE_DURATION);
}

// ── Block-propagation viz ──────────────────────────────────────────
//
// Every time the chain advances, fire arcs from a randomly-chosen online
// fleet node (the presumed "miner") to all other online nodes, plus a
// ring pulse from that origin node. Visualizes block propagation across
// the network in near-real-time. Uses the same pulse-arc style the
// reconnect path already uses.
//
// We can't know which fleet box actually mined the block without daemon-
// side telemetry plumbing — so the origin is randomized per-block. The
// visual effect is "a block landed and propagated", which is exactly what
// happened, even if the specific origin node is symbolic. Better than
// nothing; honestly framed.
let _lastBlockHeight = null;

function _fireBlockPropagation() {
  if (!_globe) return;
  const live = GNODES.filter(n => n.online);
  if (live.length < 2) return;

  // Pick a random online node as the symbolic origin.
  const origin = live[Math.floor(Math.random() * live.length)];
  const peers = live.filter(n => n.label !== origin.label);

  // Bright pulse arcs from origin → all peers.
  const arcs = peers.map(n => ({
    startLat: origin.lat, startLng: origin.lng,
    endLat:   n.lat,      endLng:   n.lng,
    pulse: true,
  }));
  _globe.arcsData(buildLiveArcs(arcs));

  // Ring pulse from the origin node — single intense ring that fades out.
  // Append to the existing rings (online-node radar halos) without
  // disrupting them. The ring auto-fades after one period.
  const baseRings = GNODES.filter(n => n.online);
  const blockRing = {
    lat: origin.lat,
    lng: origin.lng,
    color: t => `rgba(180, 255, 220, ${(1 - t) * 1.0})`,  // bright mint, like the pulse arc colour
    maxRadius: 8,
    speed:     6,
    period:    1500,
    _isBlockPulse: true,
  };
  _globe.ringsData([...baseRings, blockRing]);

  // After the pulse window, restore arcs + rings to their resting state.
  setTimeout(() => {
    if (!_globe) return;
    _globe.arcsData(buildLiveArcs());
    _globe.ringsData(GNODES.filter(n => n.online));
  }, PULSE_DURATION);
}

// Hook for the main poll() loop: call with the current chain height.
// Triggers a propagation pulse on every height advance (one per block).
// First call (when _lastBlockHeight is null) seeds the height without
// firing a pulse — otherwise we'd fire on every page refresh, which
// would be visually noisy and incorrect.
function maybeFireBlockPropagation(currentHeight) {
  if (typeof currentHeight !== 'number' || currentHeight <= 0) return;
  if (_lastBlockHeight === null) {
    _lastBlockHeight = currentHeight;
    return;
  }
  if (currentHeight > _lastBlockHeight) {
    _lastBlockHeight = currentHeight;
    _fireBlockPropagation();
  }
}

// ── NODE HEALTH POLL ─────────────────────────────────────────────────────────
// Pings every node's RPC in parallel. Updates online/offline state and
// triggers arc/point/ring refresh on the globe.
async function _pollNodeHealth() {
  const TIMEOUT_MS = 7000;
  let anyChange = false;

  await Promise.all(GNODES.map(async node => {
    let reachable = false;
    let height = node.height;
    const rpcBody = JSON.stringify({jsonrpc:'2.0', id:1, method:'get_info', params:[]});
    const rpcOpts = {method:'POST', headers:{'Content-Type':'application/json'}, body:rpcBody};
    // Try proxy first, then direct RPC fallback.
    // Fort-Knox item 4: route the origin-relative `/health/*` proxy
    // path through _API_BASE so an IPFS-served mirror hits
    // api.coincync.network's health-proxy instead of 404-ing on the
    // gateway. Direct-RPC fallback (`node._rpc`) is already an
    // absolute URL, no change needed there.
    const proxyPath = node.proxy || `/health/${node.label.toLowerCase()}`;
    const urls = [_API_BASE + proxyPath];
    if (node._rpc) urls.push(node._rpc);
    for (const url of urls) {
      if (reachable) break;
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), TIMEOUT_MS);
        const res = await fetch(url, {...rpcOpts, signal: ctrl.signal});
        clearTimeout(timer);
        const j = await res.json();
        if (j?.result) { reachable = true; height = j.result.height || height; }
      } catch(_) {}
    }

    if (reachable) {
      node.failCount = 0;
      node.height = height;
      if (!node.online) {
        // ── NODE CAME BACK ONLINE ──────────────────────────
        node.online    = true;
        node.wasOnline = true;
        anyChange = true;
        console.log(`[globe] ${node.label} reconnected ✓`);
        _refreshGlobeData();          // redraw immediately
        setTimeout(() => _fireReconnectPulse(node), 100); // then pulse
      }
    } else {
      node.failCount++;
      if (node.online && node.failCount >= FAIL_THRESHOLD) {
        // ── NODE WENT OFFLINE ─────────────────────────────
        node.online = false;
        anyChange   = true;
        console.warn(`[globe] ${node.label} went offline`);
      }
    }
  }));

  if (anyChange) _refreshGlobeData();
}

// Push updated points, rings and arcs to the live globe instance.
function _refreshGlobeData() {
  if (!_globe) return;
  _globe
    .pointsData([...GNODES])     // triggers pointColor re-eval
    .ringsData(GNODES.filter(n => n.online))  // rings only on live nodes
    .arcsData(buildLiveArcs());
}

// Start the background health poll.
function _startNodeHealthPoll() {
  _pollNodeHealth();                          // immediate first check
  setInterval(_pollNodeHealth, NODE_POLL_MS);
}


//
// PRIVACY FEATURE VISUALIZER
// Animates CoinCync's privacy stack — CLSAG rings, Bulletproofs,
// Dandelion++ stem/fluff, transaction particle, stealth address bloom.
//

const _privAnim = {
  active:      false,
  frame:       null,
  extraPoints: [],   // decoy dots + TX particle
  extraRings:  [],   // bulletproof pulses + stealth rings
  extraArcs:   [],   // dandelion stem + fluff arcs
};

// Great-circle interpolation between two lat/lng points at fraction t ∈ [0,1]
function _gcInterp(a, b, t) {
  const φ1 = a.lat*Math.PI/180, λ1 = a.lng*Math.PI/180;
  const φ2 = b.lat*Math.PI/180, λ2 = b.lng*Math.PI/180;
  const Δ  = Math.acos(Math.max(-1, Math.min(1,
    Math.sin(φ1)*Math.sin(φ2) + Math.cos(φ1)*Math.cos(φ2)*Math.cos(λ2-λ1))));
  if (Δ < 0.001) return {lat: a.lat+(b.lat-a.lat)*t, lng: a.lng+(b.lng-a.lng)*t};
  const A = Math.sin((1-t)*Δ)/Math.sin(Δ), B = Math.sin(t*Δ)/Math.sin(Δ);
  const x = A*Math.cos(φ1)*Math.cos(λ1) + B*Math.cos(φ2)*Math.cos(λ2);
  const y = A*Math.cos(φ1)*Math.sin(λ1) + B*Math.cos(φ2)*Math.sin(λ2);
  const z = A*Math.sin(φ1) + B*Math.sin(φ2);
  return {lat: Math.atan2(z,Math.sqrt(x*x+y*y))*180/Math.PI, lng: Math.atan2(y,x)*180/Math.PI};
}

// Push current overlay state to the live globe
function _flushPrivOverlays() {
  if (!_globe) return;
  _globe
    .pointsData([...GNODES, ..._privAnim.extraPoints])
    .ringsData([...GNODES.filter(n=>n.online), ..._privAnim.extraRings])
    .arcsData([...buildLiveArcs(), ..._privAnim.extraArcs]);
}
function _clearPrivOverlays() {
  _privAnim.extraPoints = [];
  _privAnim.extraRings  = [];
  _privAnim.extraArcs   = [];
  _flushPrivOverlays();
}

// ── Phase 1: CLSAG Ring ──────────────────────────────────────────────────────
// 11 violet decoy-signer dots orbit the source node, then converge and vanish.
// Ring size 11 = CoinCync's minimum.
function _phase_clsag(src) {
  return new Promise(resolve => {
    const RING_SIZE = 11, ORBIT_R = 2.6, DUR = 2200;
    const start  = performance.now();
    const decoys = Array.from({length: RING_SIZE}, (_, i) => {
      const a = (i/RING_SIZE)*Math.PI*2;
      return {lat:src.lat+Math.sin(a)*ORBIT_R, lng:src.lng+Math.cos(a)*ORBIT_R,
              color:'rgba(139,92,246,0.9)', radius:0.28, altitude:0.03, _phase:'clsag', _a:a};
    });
    // Outer orbit ring indicator
    _privAnim.extraRings.push({
      lat:src.lat, lng:src.lng,
      color: t=>`rgba(139,92,246,${(1-t)*0.7})`,
      maxRadius:6, speed:3, period:500, _phase:'clsag',
    });
    const tick = now => {
      const p = Math.min((now-start)/DUR, 1);
      decoys.forEach(d => {
        const a = d._a + p*Math.PI*1.6;
        const r = ORBIT_R * (p < 0.75 ? 1 : 1-(p-0.75)/0.25); // shrink at end
        d.lat = src.lat+Math.sin(a)*r; d.lng = src.lng+Math.cos(a)*r;
        const alpha = p<0.2 ? p/0.2 : p>0.75 ? Math.max(0,(1-p)/0.25) : 1;
        d.color = `rgba(139,92,246,${alpha.toFixed(2)})`;
      });
      _privAnim.extraPoints = [..._privAnim.extraPoints.filter(x=>x._phase!=='clsag'), ...decoys];
      _flushPrivOverlays();
      if (p < 1) { _privAnim.frame = requestAnimationFrame(tick); }
      else {
        _privAnim.extraPoints = _privAnim.extraPoints.filter(x=>x._phase!=='clsag');
        _privAnim.extraRings  = _privAnim.extraRings.filter(x=>x._phase!=='clsag');
        _flushPrivOverlays(); resolve();
      }
    };
    _privAnim.frame = requestAnimationFrame(tick);
  });
}

// ── Phase 2: Bulletproof+ Range Proof ───────────────────────────────────────
// Three rapid green rings expand from the source — the range proof commitment.
function _phase_bulletproof(src) {
  return new Promise(resolve => {
    let fired = 0;
    const fire = () => {
      const id = Math.random();
      const r  = {lat:src.lat, lng:src.lng, color:t=>`rgba(212,160,89,${(1-t)*0.85})`,
                  maxRadius:7, speed:4, period:450, _phase:'bp', _id:id};
      _privAnim.extraRings.push(r);
      _flushPrivOverlays();
      setTimeout(()=>{ _privAnim.extraRings=_privAnim.extraRings.filter(x=>x._id!==id); _flushPrivOverlays(); }, 1100);
      if (++fired < 3) setTimeout(fire, 200);
    };
    fire();
    setTimeout(resolve, 1000);
  });
}

// ── Phase 3: Dandelion++ Stem ────────────────────────────────────────────────
// TX hops privately through 2 relay nodes — thin grey whisper arcs.
function _phase_dandelion_stem(src) {
  return new Promise(resolve => {
    const relays   = GNODES.filter(n=>n.online && n.label!==src.label)
                           .sort(()=>Math.random()-0.5).slice(0,2);
    const path     = [src, ...relays];
    const stemArcs = [];
    for (let i=0; i<path.length-1; i++) stemArcs.push({
      startLat:path[i].lat, startLng:path[i].lng,
      endLat:path[i+1].lat, endLng:path[i+1].lng,
      _stem:true, _phase:'stem',
    });
    _privAnim.extraArcs.push(...stemArcs);
    _flushPrivOverlays();
    setTimeout(()=>{
      _privAnim.extraArcs=_privAnim.extraArcs.filter(x=>x._phase!=='stem');
      _flushPrivOverlays();
      resolve(path[path.length-1]);
    }, 1800);
  });
}

// ── Phase 4: Dandelion++ Fluff ───────────────────────────────────────────────
// Broadcast bursts outward from the last stem node to all live peers.
function _phase_dandelion_fluff(stemNode) {
  return new Promise(resolve => {
    const peers = GNODES.filter(n=>n.online && n.label!==stemNode.label);
    const arcs  = peers.map(n=>({
      startLat:stemNode.lat, startLng:stemNode.lng,
      endLat:n.lat, endLng:n.lng, pulse:true, _phase:'fluff',
    }));
    _privAnim.extraArcs.push(...arcs);
    _flushPrivOverlays();
    setTimeout(()=>{ _privAnim.extraArcs=_privAnim.extraArcs.filter(x=>x._phase!=='fluff'); _flushPrivOverlays(); resolve(); }, 1600);
  });
}

// ── Phase 5: Transaction Particle ───────────────────────────────────────────
// A gold pulsing dot travels the great-circle arc from src to dst.
function _phase_tx_particle(src, dst) {
  return new Promise(resolve => {
    const DUR = 2200, start = performance.now();
    const pt  = {lat:src.lat, lng:src.lng, color:'#FACC15', radius:0.65, altitude:0.09, _phase:'particle'};
    _privAnim.extraPoints.push(pt);
    _flushPrivOverlays();
    const tick = now => {
      const t    = Math.min((now-start)/DUR, 1);
      const ease = t<0.5 ? 2*t*t : -1+(4-2*t)*t;
      const pos  = _gcInterp(src, dst, ease);
      pt.lat = pos.lat; pt.lng = pos.lng;
      pt.radius = 0.65 + Math.sin(t*Math.PI*7)*0.22;   // oscillate size
      // Colour shifts gold → white as it arrives
      const g = Math.round(204 + (255-204)*t), b = Math.round(21 + (255-21)*t);
      pt.color = `rgb(250,${g},${b})`;
      _flushPrivOverlays();
      if (t < 1) { _privAnim.frame = requestAnimationFrame(tick); }
      else {
        _privAnim.extraPoints=_privAnim.extraPoints.filter(x=>x._phase!=='particle');
        _flushPrivOverlays(); resolve();
      }
    };
    _privAnim.frame = requestAnimationFrame(tick);
  });
}

// ── Phase 6: Stealth Address Bloom ──────────────────────────────────────────
// A one-time ephemeral key blooms at the destination — violet ring + dot.
function _phase_stealth(dst) {
  return new Promise(resolve => {
    const sp = {lat:dst.lat+0.9, lng:dst.lng+1.4, color:'#A855F7', radius:0.42, altitude:0.07, _phase:'stealth'};
    const sr = {lat:dst.lat+0.9, lng:dst.lng+1.4, color:t=>`rgba(168,85,247,${(1-t)*0.9})`,
                maxRadius:4.5, speed:2.2, period:650, _phase:'stealth'};
    _privAnim.extraPoints.push(sp);
    _privAnim.extraRings.push(sr);
    _flushPrivOverlays();
    setTimeout(()=>{
      _privAnim.extraPoints=_privAnim.extraPoints.filter(x=>x._phase!=='stealth');
      _privAnim.extraRings=_privAnim.extraRings.filter(x=>x._phase!=='stealth');
      _flushPrivOverlays(); resolve();
    }, 2200);
  });
}

// ── Orchestrator ─────────────────────────────────────────────────────────────
// Runs all 6 phases in sequence (3+4 and 5 run in parallel).
async function _animatePrivacyTx(src, dst) {
  if (_privAnim.active || !_globe) return;
  _privAnim.active = true;
  try {
    await _phase_clsag(src);                           // ring formation
    await _phase_bulletproof(src);                     // range proof
    const stemEnd = await _phase_dandelion_stem(src);  // private hop
    await Promise.all([
      _phase_dandelion_fluff(stemEnd),                 // broadcast
      _phase_tx_particle(src, dst),                    // tx travels
    ]);
    await _phase_stealth(dst);                         // stealth output
  } finally {
    _clearPrivOverlays();
    _privAnim.active = false;
  }
}

// ── Auto-trigger ─────────────────────────────────────────────────────────────
// Demo fires every 28 s between two random online nodes, and once on load.
function _schedulePrivacyDemo() {
  const pick = () => {
    const live = GNODES.filter(n=>n.online);
    if (live.length < 2) return;
    const src = live[Math.floor(Math.random()*live.length)];
    let   dst; do { dst=live[Math.floor(Math.random()*live.length)]; } while(dst.label===src.label);
    _animatePrivacyTx(src, dst);
  };
  setTimeout(pick, 6000);           // first demo shortly after load
  setInterval(pick, 28000);         // repeat every 28 s
}
