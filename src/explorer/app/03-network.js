// ── MEMPOOL ───────────────────────────────────────────────────
let _mpAutoInterval = null;
function toggleMempoolAuto(on) {
  if (_mpAutoInterval) { clearInterval(_mpAutoInterval); _mpAutoInterval = null; }
  if (on) { _mpAutoInterval = setInterval(loadMempool, 10000); }
}

async function loadMempool(){
  const el=$('mp-body');const cnt=$('mp-count');const sub=$('mp-sub');
  const syncTs=$('mp-last-sync');const syncBtn=$('mp-sync-btn');
  if(!el)return;
  // Disable sync button while loading
  if(syncBtn){syncBtn.disabled=true;syncBtn.style.opacity='0.5';}
  const d=await rpc('get_mempool_info');
  if(!d){el.innerHTML='<div class="loading">Unable to load</div>';if(syncBtn){syncBtn.disabled=false;syncBtn.style.opacity='1';}return;}
  const count=d.size||0;
  const bytes=d.bytes||0;
  const fees=d.total_fees||0;
  const feesCync=(fees/1e12).toFixed(6);
  const avgSize=count>0?Math.round(bytes/count):0;
  const risk=count===0?'clear':count<25?'low':count<100?'moderate':'high';
  if(cnt)cnt.textContent=count;
  const msrc=$('mp-source');if(msrc)msrc.textContent=RPC;
  const mf=$('mp-freshness');if(mf)mf.textContent='updated '+new Date().toLocaleTimeString();
  const mpb=$('mp-pending-badge');if(mpb)mpb.textContent=num(count);
  if(sub)sub.textContent=count+' pending transaction'+(count!==1?'s':'');
  if(syncTs)syncTs.textContent='synced '+new Date().toLocaleTimeString();
  // Update stats row
  const sc=$('mp-stat-count');if(sc)sc.textContent=num(count);
  const sb=$('mp-stat-bytes');if(sb)sb.textContent=fmtSize(bytes);
  const sf=$('mp-stat-fees');if(sf)sf.textContent=feesCync;
  const sa=$('mp-stat-avg');if(sa)sa.textContent=avgSize>0?fmtSize(avgSize):'—';
  const srisk=$('mp-stat-risk');if(srisk)srisk.textContent=risk;
  if(count===0){
    el.innerHTML='<div style="text-align:center;padding:40px;color:var(--t3);font-family:var(--mono);font-size:12px"><div style="font-size:28px;margin-bottom:8px">✓</div>Mempool is empty — all transactions confirmed</div>';
    if(syncBtn){syncBtn.disabled=false;syncBtn.style.opacity='1';}return;
  }
  el.innerHTML='<div class="loading" style="padding:12px">Loading '+count+' transactions...</div>';
  // Fetch individual txs
  const txData=await rpc('get_mempool_transactions');
  // Fee histogram — bucket pending txs by fee-per-byte rate. Empty mempool
  // = empty chart (still draws the axes so the panel doesn't look broken).
  _renderMempoolFeeHistogram(txData);
  if(txData&&txData.transactions&&txData.transactions.length>0){
    const rows=txData.transactions.map((tx,i)=>{
      const ring=tx.ring_size||11;
      const ins=tx.inputs||2;
      const outs=tx.outputs||2;
      const sz=tx.size||0;
      const firstSeen=tx.first_seen||tx.timestamp||tx.time||0;
      const seenAge=firstSeen?age(firstSeen):'pending';
      return `<tr onclick="viewTx('${tx.hash}')" style="cursor:pointer" onmouseenter="this.style.background='var(--acb)'" onmouseleave="this.style.background=''">
      <td><span style="color:var(--t3);font-size:10px;margin-right:6px">#${i+1}</span><span class="hash" style="color:var(--ac2)">${tx.hash?tx.hash.slice(0,20)+'…':'—'}</span> ${tx.hash?`<button onclick="event.stopPropagation();copyText('${tx.hash}',this)" class="btn btn-outline" style="font-size:9px;padding:1px 6px">copy</button>`:''}</td>
      <td><span class="badge ${tx.kind==='coinbase'?'badge-amber':''}">${tx.kind||'transfer'}</span></td>
      <td style="font-family:var(--mono)">${ins}→${outs}</td>
      <td style="font-family:var(--mono)">${fmtSize(sz)}</td>
      <td style="font-family:var(--mono)">${seenAge}</td>
      <td>
        <div style="display:flex;flex-wrap:wrap;gap:3px">
          <span class="badge" title="CLSAG ring signature with ${ring} decoys">CLSAG-${ring}</span>
          <span class="badge" title="Bulletproofs+ range proof on all outputs">BP+</span>
          <span class="badge" title="One-time stealth destination address">Stealth</span>
          <span class="badge" title="Pedersen commitment hides amount">Pedersen</span>
          ${ins===2&&outs===2?'<span class="badge badge-amber" title="Uniform 2-in/2-out shape defeats heuristics">2→2</span>':''}
        </div>
      </td>
    </tr>`;
    }).join('');
    el.innerHTML=`<table><thead><tr><th>Hash</th><th>Type</th><th>Shape</th><th>Size</th><th>Age</th><th>Privacy Features</th></tr></thead><tbody>${rows}</tbody></table>
    <div style="padding:12px 20px;display:flex;justify-content:space-between;align-items:center;font-size:11px;color:var(--t3);font-family:var(--mono);border-top:1px solid var(--b)">
      <span>${txData.transactions.length} transactions · all fully private</span>
      <span>Dandelion++ propagated · 30% fee burn</span>
    </div>`;
  } else {
    el.innerHTML='<div style="text-align:center;padding:24px;color:var(--t3);font-size:11px;font-family:var(--mono)"><div style="display:flex;flex-wrap:wrap;gap:6px;justify-content:center;margin-bottom:10px"><span class="badge">CLSAG-11</span><span class="badge">Bulletproofs+</span><span class="badge">Stealth</span><span class="badge">Pedersen</span><span class="badge badge-amber">2→2 shape</span><span class="badge">Dandelion++</span></div>All '+count+' transactions are fully private. Individual tx data pending next sync.</div>';
  }
  if(syncBtn){syncBtn.disabled=false;syncBtn.style.opacity='1';}
}

// ── PEERS ─────────────────────────────────────────────────────
async function loadPeers(){
  const el=$('peers-list');if(!el)return;
  const d=await rpc('get_peers');
  if(!d||!d.peers||!d.peers.length){el.innerHTML='<div class="loading">No peers connected</div>';return;}
  el.innerHTML=d.peers.map(p=>{
    // SECURITY: Never show real IP addresses publicly.
    // Derive a short anonymous peer ID from the address hash.
    const anonId=(s=>{let h=0;for(let i=0;i<s.length;i++){h=((h<<5)-h)+s.charCodeAt(i);h|=0;}return((h>>>0)%0xFFFF).toString(16).padStart(4,'0');})(p.addr||'');
    return `<div style="padding:12px 20px;border-bottom:1px solid var(--b)">
    <div style="display:flex;align-items:center;gap:8px;margin-bottom:3px">
      <span class="node-online"></span>
      <span class="mono" style="font-weight:600">peer-${anonId}</span>
      <span class="badge ${p.outbound?'badge-amber':''}" style="margin-left:auto;font-size:9px">${p.outbound?'out':'in'}</span>
    </div>
    <div class="age">h:${p.height} · v${p.version} · ${p.user_agent}</div>
  </div>`;}).join('');
}

// ── NODE HEALTH ───────────────────────────────────────────────
let _healthInterval=null;
let _healthMetaInterval=null;
let _healthLastProbeMs=0;
let _healthNextDueMs=0;
function _fmtSince(ms){
  const s=Math.max(0,Math.floor(ms/1000));
  if(s<60) return s+'s ago';
  if(s<3600) return Math.floor(s/60)+'m ago';
  if(s<86400) return Math.floor(s/3600)+'h ago';
  return Math.floor(s/86400)+'d ago';
}
function _updateHealthProbeMeta(){
  const el=$('health-probe-meta'); if(!el) return;
  if(!_healthLastProbeMs){ el.textContent='Last probe: — · refresh in —s'; return; }
  const now=Date.now();
  const since=_fmtSince(now-_healthLastProbeMs);
  const refreshIn=Math.max(0,Math.ceil((_healthNextDueMs-now)/1000));
  el.textContent=`Last probe: ${since} · refresh in ${refreshIn}s`;
}
async function loadHealth(){
  const grid=$('health-grid');const tbl=$('health-table');
  if(!grid)return;
  grid.innerHTML='';
  let tableRows='';
  const classifyProbeError = (err, node) => {
    const code = err && err.httpStatus ? err.httpStatus : 0;
    // Loopback-only or nginx-only hosts can't be probed directly from
    // the explorer box — their RPC is by-design not reachable. Show
    // an info-level badge so operators don't think it's an outage.
    // Per scripts/fleet-config.json: rpc_bind=127.0.0.1 hosts are
    // intentionally not externally probable.
    if (node && (node.loopbackRpc || node.apiNginxOnly)) {
      const detail = node.apiNginxOnly
        ? 'host runs nginx-only (no coincync-node service)'
        : 'rpc_bind=127.0.0.1 (loopback-only by design; see fleet-config.json)';
      return {state:'protected',label:'Probe N/A · by design',detail};
    }
    if (code === 401 || code === 403) return {state:'protected',label:'RPC Protected',detail:'auth required'};
    if (code === 404) return {state:'protected',label:'RPC Protected',detail:'route missing'};
    if (code === 502 || code === 503 || code === 504) return {state:'offline',label:'Probe failed',detail:'proxy upstream unavailable (host should be reachable but isn\'t — investigate)'};
    if (String(err && err.message || '').includes('timeout')) return {state:'offline',label:'Unreachable',detail:'timeout'};
    if (code) return {state:'offline',label:'Unreachable',detail:'http '+code};
    return {state:'offline',label:'Unreachable',detail:'network error'};
  };

  // Query each node's RPC directly via its external IP
  const queries = NODES.map(async (node) => {
    const nodeId = node.id;
    const card=document.createElement('div');card.className='health-card';
    card.innerHTML=`<div class="health-status"><div class="health-dot checking" id="hd-${nodeId}"></div>
      <div><div class="health-ip" style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--t)">${node.id}</div><div class="health-role">${node.label} · ${node.role}</div></div></div>
      <div id="hs-${nodeId}"><div class="age">Checking...</div></div>`;
    grid.appendChild(card);

    // Try proxy first (production), then optional direct RPC fallback (dev only).
    const rpcBody=JSON.stringify({jsonrpc:'2.0',id:1,method:'get_info'});
    const rpcOpts=_rpcRequestOpts(rpcBody);
    const fetchJsonRpc = async (url) => {
      let lastErr=null;
      for(let attempt=0;attempt<2;attempt++){
        try{
          const r = await Promise.race([
            fetch(url, rpcOpts),
            new Promise((_,rej)=>setTimeout(()=>rej(new Error('timeout')),5000))
          ]);
          if (!r.ok) {
            const e = new Error('http ' + r.status);
            e.httpStatus = r.status;
            throw e;
          }
          const j = await r.json();
          if (!j || !j.result) throw new Error('bad rpc response');
          return j.result;
        }catch(e){
          lastErr=e;
          // Retry only transient classes once.
          const status=e&&e.httpStatus?e.httpStatus:0;
          const transient=(String(e&&e.message||'').includes('timeout')||status===502||status===503||status===504);
          if(!transient || attempt===1) break;
          await new Promise(res=>setTimeout(res,350));
        }
      }
      throw lastErr || new Error('probe failed');
    };
    let info=null;
    let probeError=null;
    try{
      // Fort-Knox item 4: prepend _API_BASE so the origin-relative
      // `/health/*` proxy path resolves to api.coincync.network when
      // the mirror is served from an IPFS gateway.
      info = await fetchJsonRpc(_API_BASE + node.proxy);
    }catch(e){probeError=e;}
    // In production we intentionally avoid direct browser->node calls.
    // Many nodes keep RPC private or firewalled and would look falsely "offline".
    if(!info && node._rpc && EXPLORER_ALLOW_EXTERNAL_DEPS){
      try{
        info = await fetchJsonRpc(node._rpc);
      }catch(e2){probeError=e2;}
    }
    if(info){
      const dot=$('hd-'+nodeId);if(dot)dot.className='health-dot online';
      const hs=$('hs-'+nodeId);if(hs)hs.innerHTML=`
        <div class="health-stat"><span class="health-key">Height</span><span class="health-val" style="color:var(--ac2)">${num(info.height)}</span></div>
        <div class="health-stat"><span class="health-key">Peers</span><span class="health-val">${info.peer_count}</span></div>
        <div class="health-stat"><span class="health-key">Synced</span><span class="health-val">${info.synced?'✓ Yes':'Syncing'}</span></div>
        <div class="health-stat"><span class="health-key">Mempool</span><span class="health-val">${info.mempool_size||0} txs</span></div>
        <div class="health-stat"><span class="health-key">Tip age</span><span class="health-val">${info.tip_age_secs||0}s</span></div>`;
      return {id:node.id,label:node.label,loc:node.loc,role:node.role,info,online:true,state:'online'};
    }else{
      const cls=classifyProbeError(probeError, node);
      const dot=$('hd-'+nodeId);
      if(dot){
        // protected state (intentional, by-design) -> amber dot; offline
        // (real outage) -> red. Differentiates "this is fine, just not
        // probable" from "this host is broken."
        dot.className = cls.state === 'protected' ? 'health-dot protected' : 'health-dot offline';
      }
      const labelColor = cls.state === 'protected' ? 'var(--ac)' : 'var(--critical)';
      const hs=$('hs-'+nodeId);if(hs)hs.innerHTML=`<div class="age" style="color:${labelColor}" title="${cls.detail}">${cls.label}</div>`;
      return {id:node.id,label:node.label,loc:node.loc,role:node.role,info:null,online:false,state:cls.state,reason:cls.detail};
    }
  });

  const results = await Promise.allSettled(queries);
  let countOnline=0,countProtected=0,countOffline=0;
  for(const r of results){
    const d = r.status==='fulfilled' ? r.value : null;
    if(!d) continue;
    if(d.online && d.info){
      countOnline++;
      tableRows+=`<tr><td class="mono">${d.id}</td><td style="color:var(--t2)">${d.label}</td>
        <td style="color:var(--t2)">${d.role}</td><td class="hash">${num(d.info.height)}</td>
        <td>${d.info.peer_count}</td><td>${d.info.mempool_size||0}</td>
        <td><span class="badge">${d.info.synced?'✓ Synced':'Syncing'}</span></td>
        <td><span class="badge"> Online</span></td></tr>`;
    } else if(d.state==='protected'){
      countProtected++;
      tableRows+=`<tr><td class="mono">${d.id}</td><td style="color:var(--t2)">${d.label}</td>
        <td style="color:var(--t2)">${d.role}</td><td class="age">—</td><td class="age">—</td>
        <td class="age">—</td><td class="age">—</td>
        <td><span class="badge badge-amber" title="${d.reason||''}">RPC Protected</span></td></tr>`;
    } else {
      countOffline++;
      tableRows+=`<tr><td class="mono">${d.id}</td><td style="color:var(--t2)">${d.label}</td>
        <td style="color:var(--t2)">${d.role}</td><td class="age">—</td><td class="age">—</td>
        <td class="age">—</td><td class="age">—</td>
        <td><span class="badge badge-amber" title="${d.reason||''}">Offline</span></td></tr>`;
    }
  }
  const hsrc=$('health-source');if(hsrc)hsrc.textContent='/health/*';
  const hf=$('health-freshness');if(hf)hf.textContent='updated '+new Date().toLocaleTimeString();
  if(tbl)tbl.innerHTML=tableRows||'<tr><td colspan="8" class="loading">No data</td></tr>';
  const hs=$('health-summary');
  if(hs){
    hs.innerHTML=`<span class="badge">Online: ${countOnline}</span>
      <span class="badge badge-amber">RPC Protected: ${countProtected}</span>
      <span class="badge badge-red">Offline: ${countOffline}</span>`;
  }
  _healthLastProbeMs=Date.now();
  _healthNextDueMs=_healthLastProbeMs+15000;
  _updateHealthProbeMeta();

  // Auto-refresh every 15 seconds while on health page
  if(!_healthInterval) _healthInterval=setInterval(loadHealth,15000);
  if(!_healthMetaInterval) _healthMetaInterval=setInterval(_updateHealthProbeMeta,1000);
}

// ── v1.0.10 NETWORK STATUS PANEL ───────────────────────────────
//
// Five tiles driven by parallel RPC calls. Tile-level fallbacks so a
// single endpoint failure (e.g. get_shielded_anchor on an old node)
// doesn't blank the whole panel. Auto-refreshes every 15s while the
// home page is active.

// CIP-011 testnet activation heights — must match
// src/constants.rs::ROLLING_FINALITY_ENABLE_HEIGHT for testnet.
const CIP011_TESTNET_ENABLE = 50000;
const CIP011_TESTNET_ENFORCE = 75000;

let _v108Interval = null;
let _v108LastOk = 0;

async function loadV108Panel(){
  // Set "probing" state on the dot
  const dot = $('v108-status-dot');
  const statusText = $('v108-status-text');
  if (dot) dot.style.background = 'var(--ac2)';
  if (statusText) statusText.textContent = 'updating…';

  const safe = async (fn) => { try { return await fn(); } catch(e) { return null; } };

  // Fire all four in parallel; any individual failure leaves its tile as "—".
  const [finality, shielded, spark, health, metrics] = await Promise.all([
    safe(() => rpc('get_finality_info')),
    safe(() => rpc('get_shielded_anchor')),
    safe(() => rpc('get_spark_anchor')),
    safe(() => rpc('get_health')),
    safe(() => rpc('get_metrics')),
  ]);

  // Tile 1: Finality
  if (finality) {
    const tip = finality.current_height ?? 0;
    if ($('v108-tip'))         $('v108-tip').textContent = tip.toLocaleString();
    if ($('v108-checkpoint'))  $('v108-checkpoint').textContent = (finality.last_checkpoint ?? 0).toLocaleString();
    if ($('v108-maxreorg'))    $('v108-maxreorg').textContent = (finality.max_reorg_depth ?? '—').toString();
    const cipEnable = $('v108-cip011-enable');
    if (cipEnable) {
      const dist = CIP011_TESTNET_ENABLE - tip;
      if (dist > 0) {
        cipEnable.textContent = dist.toLocaleString();
        cipEnable.style.color = 'var(--ac2)';
      } else if (tip < CIP011_TESTNET_ENFORCE) {
        cipEnable.textContent = '0 (enabled, awaiting enforce)';
        cipEnable.style.color = '#7FB879';
      } else {
        cipEnable.textContent = '0 (enforced)';
        cipEnable.style.color = '#7FB879';
      }
    }
  }

  // Tile 2: Phase-2 readiness
  const sSize = shielded?.tree_size ?? 0;
  const pSize = spark?.size ?? 0;
  if ($('v108-shielded-size')) $('v108-shielded-size').textContent = sSize.toLocaleString();
  if ($('v108-spark-size'))    $('v108-spark-size').textContent    = pSize.toLocaleString();
  const phase2 = $('v108-phase2-status');
  if (phase2) {
    if (sSize === 0 && pSize === 0) {
      phase2.textContent = 'REWIND READY';
      phase2.style.background = 'rgba(127,184,121,.15)';
      phase2.style.color = '#7FB879';
      phase2.style.borderColor = 'rgba(127,184,121,.3)';
    } else {
      phase2.textContent = 'ACTIVE';
      phase2.style.background = 'rgba(212,160,89,.15)';
      phase2.style.color = 'var(--ac2)';
      phase2.style.borderColor = 'rgba(212,160,89,.4)';
    }
  }

  // Tile 3: Health
  if (health) {
    const hs = $('v108-health-status');
    if (hs) {
      hs.textContent = (health.status || 'unknown').toUpperCase();
      hs.style.color = health.status === 'healthy' ? '#7FB879' : (health.status === 'degraded' ? 'var(--ac2)' : 'var(--t3)');
    }
    if ($('v108-peers'))  $('v108-peers').textContent  = (health.peers ?? '—').toString();
    if ($('v108-synced')) $('v108-synced').textContent = health.synced ? 'yes' : 'no';
  }

  // Tile 4: Metrics snapshot
  if (metrics) {
    if ($('v108-mempool'))      $('v108-mempool').textContent      = (metrics.mempool_size ?? 0).toLocaleString();
    if ($('v108-tx-total'))     $('v108-tx-total').textContent     = (metrics.chain_total_transactions ?? 0).toLocaleString();
    if ($('v108-blocks-total')) $('v108-blocks-total').textContent = (metrics.chain_total_blocks ?? 0).toLocaleString();
  }

  // Overall status dot — green if at least one RPC succeeded
  const anyOk = !!(finality || shielded || spark || health || metrics);
  if (dot) dot.style.background = anyOk ? '#7FB879' : 'var(--t3)';
  if (statusText) statusText.textContent = anyOk ? 'live' : 'unreachable';

  if (anyOk) {
    _v108LastOk = Date.now();
    if ($('v108-updated-ago')) $('v108-updated-ago').textContent = 'just now';
  }
}

// Tick the "updated X ago" line every second without re-fetching
setInterval(() => {
  if (!_v108LastOk) return;
  const el = $('v108-updated-ago');
  if (!el) return;
  const secs = Math.round((Date.now() - _v108LastOk) / 1000);
  if (secs < 5)       el.textContent = 'just now';
  else if (secs < 60) el.textContent = `${secs}s ago`;
  else                el.textContent = `${Math.floor(secs/60)}m ago`;
}, 1000);

// Kick the panel + refresh while home is the active page
function ensureV108Polling() {
  loadV108Panel();
  if (!_v108Interval) _v108Interval = setInterval(loadV108Panel, 15000);
}

// ── DIFFICULTY CHART ──────────────────────────────────────────
function renderDiffChart(){
  const el=$('home-diff-chart');if(!el)return;
  const sorted=[...blockList].sort((a,b)=>a.height-b.height).slice(-50);
  if(sorted.length<2)return;
  const labels=sorted.map(b=>'#'+b.height);
  const data=sorted.map(b=>parseInt(b.difficulty||chainDiff));
  const isDark=document.documentElement.classList.contains('dark');
  const tc=isDark?'rgba(242,240,236,0.5)':'rgba(74,72,68,0.5)';
  const gc=isDark?'rgba(212,160,89,0.15)':'rgba(158,122,62,0.08)';
  if(diffChart)diffChart.destroy();
  diffChart=new Chart(el,{type:'line',data:{labels,datasets:[{label:'Difficulty',data,borderColor:'#9E7A3E',backgroundColor:gc,borderWidth:2,pointRadius:2,pointHoverRadius:4,fill:true,tension:0.3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{mode:'index',intersect:false,callbacks:{label:c=>'Difficulty: '+num(c.raw)}}},
    scales:{x:{ticks:{color:tc,font:{family:'IBM Plex Mono',size:10},maxTicksLimit:10},grid:{color:isDark?'rgba(46,44,42,0.5)':'rgba(228,225,216,0.5)'}},
    y:{ticks:{color:tc,font:{family:'IBM Plex Mono',size:10},callback:v=>num(v)},grid:{color:isDark?'rgba(46,44,42,0.5)':'rgba(228,225,216,0.5)'}}}
  }});
}
function renderMiningChart(){
  const el=$('mining-diff-chart');if(!el)return;
  const sorted=[...blockList].sort((a,b)=>a.height-b.height).slice(-50);
  if(sorted.length<2)return;
  const labels=sorted.map(b=>'#'+b.height);
  const data=sorted.map(b=>parseInt(b.difficulty||chainDiff));
  const isDark=document.documentElement.classList.contains('dark');
  const tc=isDark?'rgba(242,240,236,0.5)':'rgba(74,72,68,0.5)';
  const gc=isDark?'rgba(212,160,89,0.15)':'rgba(158,122,62,0.08)';
  if(miningChart)miningChart.destroy();
  miningChart=new Chart(el,{type:'line',data:{labels,datasets:[{label:'Difficulty',data,borderColor:'#9E7A3E',backgroundColor:gc,borderWidth:2,pointRadius:2,fill:true,tension:0.3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:tc,font:{family:'IBM Plex Mono',size:10},maxTicksLimit:10},grid:{color:isDark?'rgba(46,44,42,0.5)':'rgba(228,225,216,0.5)'}},
    y:{ticks:{color:tc,font:{family:'IBM Plex Mono',size:10},callback:v=>num(v)},grid:{color:isDark?'rgba(46,44,42,0.5)':'rgba(228,225,216,0.5)'}}}
  }});
}

// ── HOME BLOCK TIME CHART (#2) ────────────────────────────────
let homeBtChart=null;
function renderHomeBtChart(){
  const el=$('home-bt-chart');if(!el)return;
  const sorted=[...blockList].sort((a,b)=>a.height-b.height).slice(-50);
  if(sorted.length<3)return;
  const labels=[];const data=[];
  for(let i=1;i<sorted.length;i++){
    labels.push('#'+sorted[i].height);
    data.push(sorted[i].timestamp-sorted[i-1].timestamp);
  }
  const isDark=document.documentElement.classList.contains('dark');
  const tc=isDark?'rgba(242,240,236,0.5)':'rgba(74,72,68,0.5)';
  if(homeBtChart)homeBtChart.destroy();
  homeBtChart=new Chart(el,{type:'bar',data:{labels,datasets:[{label:'Block Time (s)',data,backgroundColor:data.map(v=>v<=180?'rgba(212,160,89,0.5)':'rgba(245,158,11,0.5)'),borderRadius:2}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},
      annotation:{}},
    scales:{x:{ticks:{color:tc,font:{size:9},maxTicksLimit:10},grid:{display:false}},
    y:{ticks:{color:tc,font:{size:9}},grid:{color:isDark?'rgba(46,44,42,0.3)':'rgba(228,225,216,0.3)'}}}
  }});
}

// ── HOME BLOCK SIZE CHART (#11) ──────────────────────────────
let homeSizeChart=null;
function renderHomeSizeChart(){
  const el=$('home-size-chart');if(!el)return;
  const sorted=[...blockList].sort((a,b)=>a.height-b.height).slice(-50);
  if(sorted.length<2)return;
  const labels=sorted.map(b=>'#'+b.height);
  const data=sorted.map(b=>b.size||393);
  const isDark=document.documentElement.classList.contains('dark');
  const tc=isDark?'rgba(242,240,236,0.5)':'rgba(74,72,68,0.5)';
  if(homeSizeChart)homeSizeChart.destroy();
  homeSizeChart=new Chart(el,{type:'line',data:{labels,datasets:[{label:'Size',data,borderColor:'#A855F7',backgroundColor:'rgba(168,85,247,0.1)',borderWidth:1.5,pointRadius:1,fill:true,tension:0.3}]},
    options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:tc,font:{size:9},maxTicksLimit:10},grid:{display:false}},
    y:{ticks:{color:tc,font:{size:9},callback:v=>fmtSize(v)},grid:{color:isDark?'rgba(46,44,42,0.3)':'rgba(228,225,216,0.3)'}}}
  }});
}

// ── NETWORK DASHBOARD (#7) ───────────────────────────────────
function updateNetDashboard(){
  const sorted=[...blockList].sort((a,b)=>a.height-b.height);
  if(sorted.length<2)return;
  // Avg block time
  const times=[];
  for(let i=1;i<sorted.length;i++) times.push(sorted[i].timestamp-sorted[i-1].timestamp);
  const avg=times.length?Math.round(times.reduce((a,b)=>a+b,0)/times.length):0;
  const nd=$('nd-avg-bt');if(nd)nd.textContent=avg+'s';
  // Total blocks
  const nt=$('nd-total');if(nt)nt.textContent=num(chainHeight);
  // Uptime (estimate from chain age)
  const genesis=sorted[0]?.timestamp||0;
  const age=genesis?Math.floor((Date.now()/1000-genesis)/3600):0;
  const nu=$('nd-uptime');if(nu)nu.textContent=age+'h';
  // Network hash
  const nh=$('nd-hash');if(nh)nh.textContent=fmtHr(chainDiff/120);
}

// ── MINING CALCULATOR ─────────────────────────────────────────
function calcMining(){
  // Guard: this is invoked from poll() every 10s, but the calc-* inputs
  // only exist on the mining-calculator page. On Home (and every other
  // page) $('calc-hr') is null and reading .value would throw, killing
  // poll() before it ever calls loadBlocks() — leaving Latest Blocks /
  // charts / dashboards stuck at "Loading...".
  const hrEl = $('calc-hr');
  if (!hrEl) return;
  const hr=parseFloat(hrEl.value||0)*parseFloat($('calc-unit').value||1000);
  const watts=parseFloat($('calc-watts').value||0);
  const elec=parseFloat($('calc-elec').value||0);
  const price=parseFloat($('calc-price').value||0);
  if(!chainDiff||!hr){return;}
  const netHr=chainDiff/120;
  const myShare=hr/netHr;
  const blocksPerDay=86400/120;
  const cyncPerDay=myShare*blocksPerDay*143;
  const costPerDay=(watts/1000)*24*elec;
  const usdPerDay=cyncPerDay*price;
  const profit=usdPerDay-costPerDay;
  const fmt=n=>n.toFixed(6);
  const fmtU=n=>'$'+n.toFixed(4);
  if($('calc-day'))$('calc-day').textContent=fmt(cyncPerDay)+' CYNC';
  if($('calc-day-usd'))$('calc-day-usd').textContent='≈ '+fmtU(usdPerDay);
  if($('calc-week'))$('calc-week').textContent=fmt(cyncPerDay*7)+' CYNC';
  if($('calc-week-usd'))$('calc-week-usd').textContent=fmtU(usdPerDay*7);
  if($('calc-month'))$('calc-month').textContent=fmt(cyncPerDay*30)+' CYNC';
  if($('calc-month-usd'))$('calc-month-usd').textContent=fmtU(usdPerDay*30);
  if($('calc-cost'))$('calc-cost').textContent=fmtU(costPerDay)+'/day electricity';
  if($('calc-profit')){
    const el=$('calc-profit');
    el.textContent=fmtU(profit)+'/day net';
    el.style.color=profit>=0?'var(--ac2)':'#EF4444';
  }
}
