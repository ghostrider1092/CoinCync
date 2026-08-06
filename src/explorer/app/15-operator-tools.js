//
// WEBSOCKET SIMULATION (#38) — polls RPC and streams via EventSource pattern
//
let _wsListeners = [];
function subscribeBlocks(callback) { _wsListeners.push(callback); return _wsListeners.length - 1; }
function unsubscribeBlocks(id) { _wsListeners[id] = null; }
// Fires from poll cycle when new block detected
function notifyBlockListeners(height, hash) {
  _wsListeners.forEach(cb => { if (cb) try { cb({ height, hash, timestamp: Date.now() }); } catch (e) {} });
  fireWebhooks(height);
}

//
// API PLAYGROUND (#42)
//
function updateApiParams(){
  const m=$('api-method').value;
  const p=$('api-params');
  p.value=m==='get_block_by_height'?'[1]':'[]';
  $('api-curl').textContent=`curl -X POST -H 'Content-Type: application/json' -d '{"jsonrpc":"2.0","method":"${m}","params":${p.value},"id":1}' https://explorer.coincync.network/api/testnet`;
}
async function runApiQuery(){
  const m=$('api-method').value;
  let params=[];
  try{params=JSON.parse($('api-params').value||'[]');}catch(e){}
  $('api-result').textContent='Running...';
  const r=await rpc(m,params);
  $('api-result').textContent=JSON.stringify(r,null,2)||'null (method may not exist)';
}

//
// STATUS PAGE (#50)
//
function updateStatusPage(info){
  const sh=$('st-height');if(sh)sh.textContent=num(info.height);
  const sd=$('st-diff');if(sd)sd.textContent=num(info.difficulty);
  const shh=$('st-hash');if(shh)shh.textContent=fmtHr(parseInt(info.difficulty)/120);
  const sm=$('st-mempool');if(sm)sm.textContent=info.mempool_size+' txs';
  const sp=$('st-peers');if(sp)sp.textContent=info.peer_count;
  const ss=$('st-synced');if(ss)ss.textContent=info.is_synced?'Yes':'Catching up';
}

//
// ADDRESS OUTPUT LOOKUP (#21)
//
async function lookupAddress() {
  const el=$('addr-lookup-input');const res=$('addr-lookup-result');
  if(!el||!res)return;
  const q=el.value.trim();
  if(!q||q.length<16){res.innerHTML='<span style="color:#EF4444">Enter an output public-key prefix (hex)</span>';return;}
  res.innerHTML='<span style="color:var(--t3)">Sampling canonical outputs...</span>';
  const sample=await loadCanonicalOutputSample(256);
  if(!sample){res.innerHTML='<span style="color:#EF4444">Locator RPC error or stale snapshot</span>';return;}
  const matches=sample.outputs.filter(output=>output.public_key.startsWith(q.slice(0,16)));
  if(matches.length===0){
    res.innerHTML=`<span style="color:var(--t3)">No match in this ${num(sample.sampled)}-output sample (${num(sample.total)} catalogued total)</span>`;
    return;
  }
  res.innerHTML=`<div style="color:var(--ac2);margin-bottom:8px">${matches.length} matching output(s) in a ${num(sample.sampled)}-output sample</div>`+
    matches.map(output=>`<div style="font-family:var(--mono);font-size:10px;padding:4px 0;border-bottom:1px solid var(--b)">pubkey: ${output.public_key.slice(0,24)}... · height: ${output.height}</div>`).join('');
}

//
// NODE VERSION DISTRIBUTION (#30)
//
let versionChart=null;
async function renderVersionChart(){
  const el=$('version-chart-canvas');if(!el)return;
  const peers=await rpc('get_peers');if(!peers||!peers.peers)return;
  const versions={};
  peers.peers.forEach(p=>{const v=p.user_agent||'unknown';versions[v]=(versions[v]||0)+1;});
  const labels=Object.keys(versions);const data=Object.values(versions);
  const colors=['#D4A059','#A855F7','#F59E0B','#EF4444','#6366F1'];
  if(versionChart)versionChart.destroy();
  versionChart=new Chart(el,{type:'doughnut',data:{labels,datasets:[{data,backgroundColor:colors.slice(0,labels.length),borderWidth:0}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{color:'#888',font:{size:10,family:'IBM Plex Mono'}}}}}});
}

//
// TOP MINERS LEADERBOARD (#33)
//
async function renderMinersLeaderboard(){
  const el=$('miners-leaderboard');if(!el)return;
  const miners={};
  const sorted=[...blockList].sort((a,b)=>a.height-b.height);
  sorted.forEach(b=>{
    if(b.transactions&&b.transactions.length>0){
      const cb=b.transactions[0];
      const addr=cb.hash?cb.hash.slice(0,16):'unknown';
      miners[addr]=(miners[addr]||0)+1;
    }else{
      miners['miner']=(miners['miner']||0)+1;
    }
  });
  const ranked=Object.entries(miners).sort((a,b)=>b[1]-a[1]).slice(0,10);
  el.innerHTML=ranked.map((m,i)=>
    `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b);font-family:var(--mono);font-size:11px">
      <span style="color:${i===0?'var(--ac2)':'var(--t2)'}">#${i+1} ${m[0]}...</span>
      <span style="color:var(--t)">${m[1]} blocks</span>
    </div>`).join('');
}

//
// MINING TUTORIAL (#44) — render when page opens
//
// Content is static HTML, no JS needed

//
// HASHRATE HISTORY (#23) — track over session
//
let _hrHistory = [];
function trackHashrate(diff) {
  if (!diff || diff <= 0) return;
  _hrHistory.push({ t: Date.now(), hr: diff / 120 });
  if (_hrHistory.length > 300) _hrHistory.shift();
  // Auto-render if network page is visible
  if ($('page-network') && $('page-network').style.display !== 'none') renderHrHistChart();
}
let hrHistChart = null;
function renderHrHistChart() {
  const el = $('hr-history-canvas');
  if (!el || _hrHistory.length < 1) return;
  const isDark = document.documentElement.classList.contains('dark');
  const tc = isDark ? 'rgba(242,240,236,0.5)' : 'rgba(74,72,68,0.5)';
  if (hrHistChart) hrHistChart.destroy();
  hrHistChart = new Chart(el, {
    type: 'line',
    data: { labels: _hrHistory.map((_, i) => i), datasets: [{
      label: 'Network H/s', data: _hrHistory.map(h => h.hr),
      borderColor: '#D4A059', backgroundColor: 'rgba(212,160,89,0.1)',
      borderWidth: 1.5, pointRadius: 0, fill: true, tension: 0.3
    }] },
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { display: false }, y: { ticks: { color: tc, font: { size: 9 }, callback: v => fmtHr(v) }, grid: { color: isDark ? 'rgba(46,44,42,0.3)' : 'rgba(228,225,216,0.3)' } } }
    }
  });
}

//
// FAUCET (#1)
//
async function requestFaucet() {
  const addrEl = document.getElementById('faucet-addr');
  const resEl = document.getElementById('faucet-result');
  const addr = addrEl ? addrEl.value.trim() : '';
  if (!addr.startsWith('tCYNC') || addr.length < 20) {
    if (resEl) resEl.innerHTML = '<span style="color:#EF4444">Enter a valid tCYNC address</span>';
    return;
  }
  if (resEl) resEl.innerHTML = '<span style="color:var(--t3)">Sending 10 CYNC...</span>';
  try {
    // POST to /faucet (no trailing slash — api nginx uses `location = /faucet`
    // as an exact-match; trailing slash gets routed to the static 404 handler).
    // The explorer's own nginx proxies /faucet to api.coincync.network/faucet
    // so the browser request stays same-origin and avoids a CORS preflight.
    const r = await fetch('/faucet', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address: addr })
    });
    const d = await r.json();
    if (d.success) {
      if (resEl) resEl.innerHTML = `<span style="color:#D4A059">Sent 10 CYNC! TX: ${d.tx_hash.slice(0,16)}...</span>`;
      showToast('🚰', 'Faucet sent 10 CYNC', d.tx_hash.slice(0, 24) + '...', 5000);
    } else {
      if (resEl) resEl.innerHTML = `<span style="color:#EF4444">${d.error || 'Failed'}</span>`;
    }
  } catch (e) {
    if (resEl) resEl.innerHTML = `<span style="color:#EF4444">Network error: ${e.message}</span>`;
  }
}

//
// FULLSCREEN GLOBE (#20)
//
function toggleGlobeFullscreen() {
  const wrap = $('globe-wrap');
  const btn = $('globe-fs-btn');
  if (!wrap) return;
  if (document.fullscreenElement) {
    document.exitFullscreen();
    if (btn) btn.textContent = '⛶ Fullscreen';
  } else {
    wrap.requestFullscreen().catch(() => {});
    if (btn) btn.textContent = '✕ Exit';
  }
}

//
// CHAIN EVENTS TIMELINE (#25)
//
async function loadChainEvents() {
  const el = $('chain-events-list');
  if (!el) return;
  const data = await rpc('get_chain_events', [50]);
  if (!data || !data.events || data.events.length === 0) {
    el.innerHTML = '<div style="padding:16px;text-align:center;color:var(--t3);font-size:11px">No chain events yet — clean consensus</div>';
    return;
  }
  el.innerHTML = data.events.slice(0, 20).map(e =>
    `<div style="padding:8px 14px;border-bottom:1px solid var(--b);font-family:var(--mono);font-size:10px;display:flex;justify-content:space-between">
      <span style="color:var(--ac2)">${e.event_type || 'event'}</span>
      <span style="color:var(--t3)">h=${e.height || '?'}</span>
    </div>`
  ).join('');
}

//
// BURN STATS
//
async function loadBurnStats(){
  const d=await rpc('get_burn_stats');
  const banner=$('burn-status-banner');
  if(!d){
    if(banner)banner.innerHTML='Unable to load burn stats';
    return;
  }
  // Status banner
  if(banner){
    if(d.active){
      banner.style.background='rgba(212,160,89,.08)';
      banner.style.borderColor='rgba(212,160,89,.25)';
      banner.style.color='var(--ac2)';
      banner.innerHTML='🔥 Fee burn is <strong>ACTIVE</strong> since block '+num(d.activation_height)+' — 30% of all transaction fees are permanently destroyed';
    } else {
      const remaining=d.activation_height-d.current_height;
      banner.innerHTML=' Fee burn activates at block <strong>'+num(d.activation_height)+'</strong> — '+num(remaining)+' blocks remaining (~'+Math.round(remaining*2/60)+' minutes)';
    }
  }
  // Live stats
  const s=id=>$(id);
  if(s('burn-active'))s('burn-active').innerHTML=d.active?'<span style="color:var(--ac2);font-weight:600">ACTIVE</span>':'<span style="color:#F0C040">Pending (block '+num(d.activation_height)+')</span>';
  if(s('burn-activation-h'))s('burn-activation-h').textContent=num(d.activation_height);
  if(s('burn-current-h'))s('burn-current-h').textContent=num(d.current_height);
  if(s('burn-reward'))s('burn-reward').textContent=num(d.block_reward)+' atomic ('+((d.block_reward||0)/1e12).toFixed(0)+' CYNC)';
  if(s('burn-split-normal'))s('burn-split-normal').textContent='Miner '+d.miner_pct_normal+'% / Burn '+d.burn_pct_normal+'%';
  if(s('burn-split-congested'))s('burn-split-congested').textContent='Miner '+d.miner_pct_congested+'% / Burn '+d.burn_pct_congested+'%';
  if(s('burn-congestion-thresh'))s('burn-congestion-thresh').textContent=d.congestion_threshold_pct+'% block fullness';
  if(s('burn-supply'))s('burn-supply').textContent=num(Math.round(atomicToCyncDisplayNumber(d.circulating_supply)))+' CYNC';
  if(s('burn-max-supply'))s('burn-max-supply').textContent='100,000,000 CYNC';
  if(s('burn-deflation-thresh'))s('burn-deflation-thresh').innerHTML=num(Math.round((d.deflation_threshold_fee_per_block||0)/1e12))+' CYNC/block <span style="color:var(--t3);font-size:10px">— fees above this = deflation</span>';
}

//
// SOAK STATUS — populates page-soak's per-box table by polling each fleet
// node's /health/<name> endpoint. Reads chain tip + peer count + tip age
// for each box; rolls a green/yellow/red status based on tip-age threshold.
// Fleet IPs aren't displayed publicly — operators see them via SSH; this
// page shows logical names only.
//
const FLEET_BOXES = [
  { name:'seed1',    region:'New Jersey, USA',        role:'Seed (US-East)',     proxy:'/health/seed1' },
  { name:'seed2',    region:'Amsterdam, Netherlands', role:'Seed (Europe)',      proxy:'/health/seed2' },
  { name:'seed3',    region:'Tokyo, Japan',           role:'Seed (Asia-Pacific)',proxy:'/health/seed3' },
  { name:'explorer', region:'Dallas, USA',            role:'Explorer + Relay',   proxy:'/health/explorer' },
  { name:'api',      region:'Frankfurt, Germany',     role:'Public API + Relay', proxy:'/health/api' },
];

async function _pollFleetBox(box){
  try{
    const resp = await fetch(box.proxy, {
      method:'POST',
      headers:_rpcRequestOpts(JSON.stringify({jsonrpc:'2.0',id:1,method:'get_info'})).headers,
      body: JSON.stringify({jsonrpc:'2.0',id:1,method:'get_info'}),
    });
    if(!resp.ok) return null;
    const d = await resp.json();
    return d && d.result;
  }catch(_){ return null; }
}

function _statusBadge(ageS, peers){
  if(ageS == null) return '<span style="color:#C45C4F">unreachable</span>';
  if(ageS < 240 && peers >= 3) return '<span style="color:var(--ac2);font-weight:600">healthy</span>';
  if(ageS < 600) return '<span style="color:#E0A040">warming</span>';
  return '<span style="color:#C45C4F">stale</span>';
}

async function loadSoakStatus(){
  const tbody = $('soak-rows');
  if(!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" class="loading">Polling fleet…</td></tr>';
  const results = await Promise.all(FLEET_BOXES.map(_pollFleetBox));
  const rows = FLEET_BOXES.map((box, i) => {
    const r = results[i];
    if(!r) return `<tr><td><strong>${box.name}</strong></td><td colspan="4" style="color:var(--t3)">—</td><td>${_statusBadge(null,0)}</td></tr>`;
    const ageS = r.tip_age_secs ?? null;
    return `<tr>
      <td><strong>${box.name}</strong></td>
      <td class="mono">${num(r.height ?? 0)}</td>
      <td>${r.peer_count ?? 0}</td>
      <td>${ageS != null ? ageS + 's' : '—'}</td>
      <td>${(r.is_synced ?? r.synced) ? '<span style="color:var(--ac2)">✓ Yes</span>' : '<span style="color:#E0A040">Catching up</span>'}</td>
      <td>${_statusBadge(ageS, r.peer_count ?? 0)}</td>
    </tr>`;
  }).join('');
  tbody.innerHTML = rows;
}

async function loadFleetLeaderboard(){
  const tbody = $('lb-rows');
  if(!tbody) return;
  tbody.innerHTML = '<tr><td colspan="7" class="loading">Polling…</td></tr>';
  const results = await Promise.all(FLEET_BOXES.map(_pollFleetBox));
  const rows = FLEET_BOXES.map((box, i) => {
    const r = results[i];
    if(!r) return `<tr><td><strong>${box.name}</strong></td><td>${box.region}</td><td>${box.role}</td><td colspan="3" style="color:var(--t3)">unreachable</td><td>${_statusBadge(null,0)}</td></tr>`;
    const ageS = r.tip_age_secs ?? null;
    return `<tr>
      <td><strong>${box.name}</strong></td>
      <td>${box.region}</td>
      <td>${box.role}</td>
      <td class="mono">${num(r.height ?? 0)}</td>
      <td>${ageS != null ? ageS + 's' : '—'}</td>
      <td>${r.peer_count ?? 0}</td>
      <td>${_statusBadge(ageS, r.peer_count ?? 0)}</td>
    </tr>`;
  }).join('');
  tbody.innerHTML = rows;
}

//
