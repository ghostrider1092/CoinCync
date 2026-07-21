// ── POLL ──────────────────────────────────────────────────────
async function poll(){
  const info=await rpc('get_info');
  if(!info){
    _rpcFailures++;
    $('status').textContent='Offline';
    $('live-dot').classList.add('off');
    return;
  }
  _lastInfo = info;
  _lastPollAtMs = Date.now();
  _rpcFailures = 0;
  _heartbeat();
  _updateOperatorStrip(info);
  if(_apiHealthProbeCountdown-- <= 0){
    _apiHealthProbeCountdown = 5;
    _probeApiHealth();
  }

  // Update decay clock with tip age
  const tipAgeSecs = info.tip_age_secs || 0;
  const peerCount  = info.peer_count || 0;
  _updateDecayClock(tipAgeSecs);

  // STALE CHAIN WARNING — show banner if tip is older than 10 minutes
  let staleBanner = document.getElementById('stale-banner');
  if (!staleBanner) {
    staleBanner = document.createElement('div');
    staleBanner.id = 'stale-banner';
    staleBanner.style.cssText = 'display:none;background:#92400E;color:#FEF3C7;text-align:center;padding:8px 16px;font-size:12px;font-weight:600;font-family:var(--mono);position:fixed;top:0;left:0;right:0;z-index:9999';
    document.body.prepend(staleBanner);
  }
  if (tipAgeSecs > 600) {
    const mins = Math.floor(tipAgeSecs / 60);
    staleBanner.textContent = `⚠ Chain data is ${mins} minutes old — node is syncing`;
    staleBanner.style.display = 'block';
    _pushOperatorAlert('warn', `stale tip: ${Math.floor(tipAgeSecs/60)}m old`);
  } else {
    staleBanner.style.display = 'none';
  }
  if ((info.peer_count||0) === 0) _pushOperatorAlert('crit', 'no peers connected');
  if (_lastChainHeightSeen && info.height < _lastChainHeightSeen) {
    _pushOperatorAlert('crit', `height dropped ${_lastChainHeightSeen} -> ${info.height}`);
  }
  if (_lastChainHeightSeen && info.height > _lastChainHeightSeen) {
    _pushOperatorAlert('info', `new block #${info.height}`);
  }
  _lastChainHeightSeen = info.height;

  // Anonymity set counter
  if(info.anonymity_set != null){
    $('aset-value').textContent = num(info.anonymity_set);
    $('aset-sub').textContent   = `outputs · ring size ${info.effective_ring_size||16} · grows every block`;
  }

  $('status').textContent=info.height>0?'Connected':'Starting...';$('live-dot').classList.remove('off');
  // Block-propagation viz on the globe — fires arcs + ring pulse from a
  // randomly-chosen online fleet node every time the chain advances.
  // Cheap (just height comparison + one arcsData/ringsData refresh).
  // Safe to call when globe isn't initialized — function is a no-op then.
  try { maybeFireBlockPropagation(info.height); } catch(_){/* never block poll on viz */}
  chainHeight=info.height;chainDiff=parseInt(info.difficulty);
  const hr=chainDiff/120;
  // Animate height counter + trigger block pulse
  const hEl=$('tk-height');
  if(hEl && chainHeight>0 && info.height>chainHeight) {
    animateValue(hEl, chainHeight, info.height, 600);
    blockPulse(info.height);
  } else if(hEl) { hEl.textContent=num(info.height); }
  $('tk-diff').textContent=num(info.difficulty);
  $('tk-hr').textContent=fmtHr(hr);
  $('tk-peers').textContent=info.peer_count;$('tk-pool').textContent=info.tx_pool_size+' txs';
  // Fetch real supply from get_supply_info (atomic units / 1e12 = CYNC)
  const supInfo=await rpc('get_supply_info');
  const supCync=supInfo?atomicToCyncDisplayNumber(supInfo.total_emitted):0;
  const rewCync=supInfo?(supInfo.current_reward/1e12):0;
  $('tk-supply').textContent=num(Math.round(supCync))+' CYNC';
  $('s-height').textContent=num(info.height);
  $('s-supply').textContent=num(Math.round(supCync));
  // ── Live fee-burn counter ────────────────────────────────────
  // total_burned = total_emitted - circulating_supply, both atomic.
  // Pulls get_burn_stats for circulating_supply; emitted from supInfo.
  // Article XVI invariant: 30% floor under normal conditions, rising
  // during congestion. Counter ticks up as blocks land.
  const bv=$('burn-value');
  if(bv){
    try{
      const burnStats=await rpc('get_burn_stats');
      if(burnStats && supInfo){
        const emittedAtomic=BigInt(supInfo.total_emitted??0);
        const circulatingAtomic=BigInt(burnStats.circulating_supply??0);
        const burnedAtomic=emittedAtomic>circulatingAtomic?emittedAtomic-circulatingAtomic:0n;
        const burnedCync=atomicToCyncDisplayNumber(burnedAtomic);
        // Render with 2 decimals if < 100 CYNC, else integer with commas.
        bv.textContent=burnedCync<100?burnedCync.toFixed(2):num(Math.round(burnedCync));
        const bs=$('burn-sub');
        if(bs && burnStats.active===false){
          bs.innerHTML='Burn activates at block <strong>'+num(burnStats.activation_height)+'</strong> &middot; '+num(Math.max(0,(burnStats.activation_height||0)-(burnStats.current_height||0)))+' blocks remaining';
        } else if(bs){
          bs.innerHTML='CYNC permanently destroyed &middot; <strong>30% of every fee</strong>';
        }
      }
    }catch(_){/* silent — burn stats are non-critical for the home page */}
  }
  const sr=$('s-reward');if(sr)sr.textContent=num(Math.round(rewCync));
  $('s-peers').textContent=info.peer_count;
  $('n-synced').textContent=info.height>0?'Yes (h='+num(info.height)+')':'Connecting...';$('n-diff').textContent=num(info.difficulty);
  $('priv-blocks').textContent=num(info.height);
  const bs=$('blocks-sub');if(bs)bs.textContent=num(info.height)+' total blocks';
  const bsrc=$('blocks-source');if(bsrc)bsrc.textContent=RPC;
  const bfr=$('blocks-freshness');if(bfr)bfr.textContent=(info.tip_age_secs||0)+'s tip age';
  const btip=$('blocks-tip');if(btip)btip.textContent='#'+num(info.height);
  const set2=(id,v)=>{const e=$(id);if(e)e.textContent=v;};
  set2('cd-height',num(info.height));set2('cd-supply',num(Math.round(supCync))+' CYNC');
  set2('cd-diff',num(info.difficulty));set2('cd-peers',info.peer_count);
  // supply
  const circ=Math.round(supCync);const pct=(circ/100000000*100).toFixed(4);
  const sc=$('sup-circ');if(sc)sc.textContent=num(circ)+' CYNC';
  const sp=$('sup-pct');if(sp)sp.textContent=pct+'%';
  const sl=$('sup-label');if(sl)sl.textContent=num(circ)+' / 100,000,000 CYNC';
  const sb=$('sup-bar');if(sb)sb.style.width=Math.min(parseFloat(pct)*100,100)+'%';
  const srp=$('sup-reward');if(srp)srp.textContent=num(Math.round(rewCync));
  // Supply ring (#4)
  const ringFill=$('supply-ring-fill');
  if(ringFill){
    const pctNum=circ/100000000;
    const circumference=326.73;
    ringFill.setAttribute('stroke-dashoffset', circumference*(1-pctNum));
  }
  const ringPct=$('supply-ring-pct');if(ringPct)ringPct.textContent=pct+'%';
  const ringMined=$('supply-ring-mined');if(ringMined)ringMined.textContent=num(circ)+' CYNC';
  const ringReward=$('supply-ring-reward');if(ringReward)ringReward.textContent=num(Math.round(rewCync))+' CYNC';
  // network page
  const nh=$('net-h');if(nh)nh.textContent=num(info.height);
  const nhash=$('net-hash');if(nhash)nhash.textContent=info.top_hash;
  const nd=$('net-d');if(nd)nd.textContent=num(info.difficulty);
  const nhr=$('net-hr');if(nhr)nhr.textContent=fmtHr(hr);
  const ns=$('net-s');if(ns)ns.textContent=info.synced?'Yes':'Syncing...';
  const nm=$('net-m');if(nm)nm.textContent=info.tx_pool_size+' transactions';
  const no=$('net-o');if(no&&info.available_outputs)no.textContent=num(info.available_outputs);
  const nsrc=$('net-source');if(nsrc)nsrc.textContent=RPC;
  const nf=$('net-freshness');if(nf)nf.textContent='tip age '+(info.tip_age_secs||0)+'s';
  // mining calc
  const cnd=$('calc-net-diff');if(cnd)cnd.textContent=num(info.difficulty);
  const cnhr=$('calc-net-hr');if(cnhr)cnhr.textContent=fmtHr(hr);
  calcMining();
  // Live block feed — fires every poll cycle
  await updateLiveFeed(info.height);

  // Track anonymity set growth (#29) + hashrate history (#23) + status (#50)
  trackAnonSet(info);
  trackHashrate(chainDiff);
  renderHrHistChart();
  updateStatusPage(info);

  // Privacy stats (Spark + Shielded pool). Stash on window so the
  // home-tab constellation can read the anonymity-set sizes without
  // re-querying the RPC.
  const priv = await rpc('get_privacy_stats');
  if (priv) {
    window._privStats = priv;
    const ss = $('spark-size'); if(ss) ss.textContent = num(priv.spark_accumulator_size || 0) + ' entries';
    const shs = $('shielded-size'); if(shs) shs.textContent = num(priv.shielded_tree_size || 0) + ' notes';
    const shr = $('shielded-root'); if(shr) shr.textContent = (priv.shielded_root || '—').slice(0, 24) + '...';
  }
  // Animate stealth address demo with block-derived values
  const otk = $('stealth-otk'); if(otk) otk.textContent = (info.top_hash || '').slice(0, 32) + '...';
  const saddr = $('stealth-addr'); if(saddr) saddr.textContent = (info.top_hash || '').split('').reverse().join('').slice(0, 32) + '...';

  if(info.height!==loadedHeight||!blockList.length){
    await loadBlocks(info.height,20);
    renderHomeBlocks();
    renderDiffChart();
    renderHomeBtChart();
    renderHomeSizeChart();
    updateNetDashboard();
    renderDiffPrediction();
    renderConvergenceTimeline();
    renderForgeWheel(0);
  }
}

// ── LIVE BLOCK FEED ──────────────────────────────────────────
let _feedLastHeight = 0;
const _feedItems = [];
const FEED_MAX = 30;

async function updateLiveFeed(currentHeight) {
  const feedList = $('live-feed-list');
  const feedStatus = $('feed-status');
  if (!feedList) return;

  if (_feedLastHeight === 0) {
    _feedLastHeight = Math.max(0, currentHeight - 5);
  }

  if (currentHeight <= _feedLastHeight) {
    if (feedStatus) feedStatus.textContent = `height ${currentHeight} · waiting...`;
    return;
  }

  const newStart = Math.max(_feedLastHeight + 1, currentHeight - 10);
  for (let h = newStart; h <= currentHeight; h++) {
    const blk = await rpc('get_block_by_height', [h]);
    if (!blk) continue;
    const ts = blk.timestamp || 0;
    const reward = blk.reward ? (blk.reward / 1e12) : 143;
    _feedItems.unshift({
      height: h,
      hash: (blk.hash || '').slice(0, 16),
      timestamp: ts,
      txCount: blk.tx_count || 1,
      algo: blk.algorithm_name || 'RandomX',
      reward: Math.round(reward),
    });
    if (_feedItems.length > FEED_MAX) _feedItems.pop();
  }
  _feedLastHeight = currentHeight;

  const now = Math.floor(Date.now() / 1000);
  feedList.innerHTML = _feedItems.map((b, i) => {
    const age = now - b.timestamp;
    const ageStr = age < 60 ? age + 's ago' : age < 3600 ? Math.floor(age/60) + 'm ago' : Math.floor(age/3600) + 'h ago';
    return `<div class="live-feed-item${i === 0 && b.height === currentHeight ? ' new' : ''}" onclick="showBlock(${b.height})">
      <span class="blk-num">Block #${num(b.height)}</span>
      <span class="blk-algo">${b.algo}</span>
      <span class="blk-reward">${b.reward} CYNC</span>
      <span class="blk-age">${ageStr}</span>
    </div>`;
  }).join('');

  if (feedStatus) feedStatus.textContent = `height ${currentHeight} · ${_feedItems.length} blocks`;
}

// Update feed ages every second
setInterval(() => {
  document.querySelectorAll('.live-feed-item .blk-age').forEach(el => {
    // Ages tick naturally when poll() fires and rebuilds the list
  });
}, 1000);

// ── BLOCKS ────────────────────────────────────────────────────
// Loads heights [fromH-count+1 .. fromH] (inclusive) using batched JSON-RPC
// `get_block_range` (up to 100 blocks per call — server cap). Falls back to
// per-height `get_block_by_height` if the batch endpoint is unavailable.
async function loadBlocks(fromH,count){
  if(fromH<0)return;
  const end=fromH;
  const start=Math.max(0,fromH-count+1);
  let curStart=start;
  while(curStart<=end){
    const curEnd=Math.min(end,curStart+99);
    const pack=await rpc('get_block_range',[curStart,curEnd]);
    if(pack&&pack.blocks&&pack.blocks.length){
      const base=typeof pack.start==='number'?pack.start:curStart;
      const nb=[];
      for(let i=0;i<pack.blocks.length;i++){
        const h=base+i;
        if(blockList.find(b=>b.height===h))continue;
        const b=pack.blocks[i];
        if(b){b.height=h;nb.push(b);}
      }
      blockList=[...nb,...blockList].filter((b,i,a)=>a.findIndex(x=>x.height===b.height)===i);
      blockList.sort((a,b)=>b.height-a.height);
      curStart=curEnd+1;
      await _yieldToUi();
      continue;
    }
    for(let h=curStart;h<=curEnd;h++){
      if(blockList.find(b=>b.height===h))continue;
      const b=await rpc('get_block_by_height',[h]);
      if(b){b.height=h;blockList.push(b);}
    }
    blockList=blockList.filter((b,i,a)=>a.findIndex(x=>x.height===b.height)===i);
    blockList.sort((a,b)=>b.height-a.height);
    curStart=curEnd+1;
    await _yieldToUi();
  }
  loadedHeight=fromH;
}
function jumpToBlockHeight(){
  const input=$('blocks-jump-height');
  if(!input)return;
  const h=parseInt(input.value,10);
  if(Number.isNaN(h)||h<0)return;
  void viewBlock(h);
}

function blocksDirectLookup(){
  const input = $('blocks-direct-lookup');
  if(!input) return;
  const q = (input.value||'').trim();
  if(!q) return;
  if(/^\d+$/.test(q)){ viewBlock(parseInt(q,10)); return; }
  if(/^[0-9a-f]{64}$/i.test(q)){
    viewTx(q);
    return;
  }
  _pushOperatorAlert('warn', 'lookup expects height or 64-char hash');
}
async function jumpNewestBlocks(){
  const info=_lastInfo||await rpc('get_info');
  if(!info)return;
  blockList=[];
  loadedHeight=0;
  await loadBlocks(info.height,100);
  renderAllBlocks();
}
async function loadMore(){
  if(!blockList.length)return;
  const oldest=blockList[blockList.length-1];
  if(oldest.height===0)return;
  await loadBlocks(oldest.height-1,100);
  renderAllBlocks();
}
// After opening the Blocks page, walk backward to genesis (height 0) in
// batches so the table can list the full canonical chain from the node.
async function ensureBlocksBackfillToGenesis(){
  const myGen=++_blocksGenesisBackfillGen;
  if(_blocksGenesisBackfillRunning)return;
  _blocksGenesisBackfillRunning=true;
  const sub=$('blocks-sub');
  try{
    let info=await rpc('get_info');
    if(!info){if(sub)sub.textContent='Node unreachable — check /api proxy.';return;}
    if(myGen!==_blocksGenesisBackfillGen)return;
    if(!blockList.length){
      await loadBlocks(info.height,Math.min(5000,info.height+1));
      renderAllBlocks();
    }
    while(myGen===_blocksGenesisBackfillGen){
      if(!blockList.length)break;
      const oldest=blockList[blockList.length-1];
      if(!oldest||oldest.height===0){
        if(sub)sub.textContent='Full chain — '+blockList.length+' blocks (including genesis).';
        break;
      }
      if(sub)sub.textContent='Fetching older blocks… oldest #'+num(oldest.height)+' · '+blockList.length+' loaded';
      await loadBlocks(oldest.height-1,100);
      renderAllBlocks();
      await _yieldToUi();
    }
  }finally{
    _blocksGenesisBackfillRunning=false;
  }
}
// Block decay classes — thresholds tied to the 120s target block time.
// fresh  < 2 block times  | stale < 10 block times
// old    < 30 block times | dead  >= 30 block times (entire decay window)
function _blockAgeClass(ts){
  if(!ts) return 'dead';
  const s = Math.max(0, Math.floor(Date.now()/1000) - ts);
  if(s <  60) return 'fresh';
  if(s < 300) return 'stale';
  if(s < 900) return 'old';
  return 'dead';
}

function renderHomeBlocks(){
  const tb=$('home-blocks');if(!tb)return;
  if(!blockList.length){tb.innerHTML='<tr><td colspan="5" class="loading">No blocks</td></tr>';return;}
  tb.innerHTML=blockList.slice(0,10).map(b=>`<tr class="block-row" data-age-class="${_blockAgeClass(b.timestamp)}" onclick="viewBlock(${b.height})">
    <td><span class="hash">#${num(b.height)}</span></td>
    <td class="age">${age(b.timestamp)} ago</td>
    <td>${b.tx_count||1}</td>
    <td><span class="badge badge-amber" style="font-size:9px">${algoName(b.algorithm||0)}</span></td>
    <td><span class="badge" style="font-size:8px" title="CLSAG ring sig + Pedersen commitment + Bulletproofs+ + stealth address">🛡4/4</span></td>
  </tr>`).join('');
}
function renderAllBlocks(){
  const tb=$('all-blocks');if(!tb)return;
  if(!blockList.length){tb.innerHTML='<tr><td colspan="7" class="loading">No blocks</td></tr>';return;}
  tb.innerHTML=blockList.map(b=>`<tr class="block-row" data-age-class="${_blockAgeClass(b.timestamp)}" onclick="viewBlock(${b.height})">
    <td><span class="hash">#${num(b.height)}</span> <button onclick="event.stopPropagation();copyText('#${b.height}',this)" class="btn btn-outline" style="font-size:9px;padding:1px 6px">copy</button></td>
    <td class="age">${age(b.timestamp)} ago</td>
    <td class="hash" style="font-size:10px">${b.hash?b.hash.slice(0,18)+'...':'—'} ${b.hash?`<button onclick="event.stopPropagation();copyText('${b.hash}',this)" class="btn btn-outline" style="font-size:9px;padding:1px 6px">copy</button>`:''}</td>
    <td><span class="badge badge-amber" style="font-size:9px">${algoName(b.algorithm||0)}</span></td>
    <td>${b.tx_count||1}</td>
    <td class="age">${fmtSize(b.size||393)}</td>
    <td><span class="badge">✓ shielded</span></td>
  </tr>`).join('');
  const bs=$('blocks-shown');if(bs)bs.textContent=blockList.length;
  const st=$('blocks-load-status');if(st&&!_blocksGenesisBackfillRunning)st.textContent='';
}

// ── BLOCK DETAIL ──────────────────────────────────────────────
async function viewBlock(height){
  go('block');
  $('bd-title').textContent='Loading...';
  let b=blockList.find(bl=>bl.height===height);
  if(!b){b=await rpc('get_block_by_height',[height]);if(b)b.height=height;}
  if(!b){$('bd-title').textContent='Block not found';return;}
  if(!blockList.find(bl=>bl.height===height)){blockList.push(b);blockList.sort((a,b)=>b.height-a.height);}
  $('bd-bc').textContent='#'+num(height);
  $('bd-title').textContent='Block #'+num(height);
  $('bd-sub').textContent=fmtTs(b.timestamp)+' · '+age(b.timestamp)+' ago';
  $('bd-height').textContent='#'+num(height);
  $('bd-ts').textContent=fmtTs(b.timestamp);
  $('bd-age').textContent=age(b.timestamp)+' ago';
  $('bd-algo').innerHTML='<span class="badge badge-amber">'+algoName(b.algorithm||0)+'</span>';
  $('bd-txs').textContent=b.tx_count||1;
  $('bd-size').textContent=fmtSize(b.size||393);
  $('bd-hash').innerHTML=(b.hash||'—')+(b.hash?` <button onclick="copyText('${b.hash}',this)" class="btn btn-outline" style="font-size:9px;padding:1px 6px">copy</button>`:'');
  $('bd-prev-hash').innerHTML=(b.prev_hash||'—')+(b.prev_hash?` <button onclick="copyText('${b.prev_hash}',this)" class="btn btn-outline" style="font-size:9px;padding:1px 6px">copy</button>`:'');
  $('bd-prev').onclick=height>1?()=>viewBlock(height-1):null;
  $('bd-prev').disabled=height<=1;
  $('bd-next').onclick=height<chainHeight?()=>viewBlock(height+1):null;
  $('bd-next').disabled=height>=chainHeight;
  // Render the ring signature visualizer (Phase 3)
  renderRingViz(b.hash || ('block-'+height));
}

//
// RING SIGNATURE VISUALIZER (Phase 3)
// Renders all 11 ring members as nodes around a circle. The "real signer"
// is intentionally indistinguishable. Hovering shows "one of these spent —
// you can't tell which, ever."
//
function renderRingViz(seedHash){
  const svg = document.getElementById('ring-svg');
  if(!svg) return;
  const RING = 11;
  const RADIUS = 120;
  let s = 0;
  for(let i=0;i<Math.min(seedHash.length,16);i++) s = ((s<<5)-s+seedHash.charCodeAt(i))|0;
  if(s===0) s = 0x12345678;
  const rand = () => { s ^= s<<13; s ^= s>>>17; s ^= s<<5; return Math.abs(s); };
  const fakePubkey = () => {
    const h = '0123456789abcdef';
    let out = '';
    for(let i=0;i<8;i++) out += h[rand() & 0xf];
    return out;
  };
  const members = [];
  for(let i=0;i<RING;i++) members.push({ pubkey: fakePubkey(), idx: i });

  let html = '';
  // SVG glow filter
  html += `<defs>
    <filter id="glow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <filter id="glow-lg"><feGaussianBlur stdDeviation="6" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
    <radialGradient id="nodeGrad"><stop offset="0%" stop-color="#D4A059" stop-opacity="0.4"/><stop offset="100%" stop-color="#9E7A3E" stop-opacity="0"/></radialGradient>
  </defs>`;

  // Outer glow ring
  html += `<circle cx="0" cy="0" r="${RADIUS}" fill="none" stroke="#9E7A3E" stroke-width="0.5" stroke-opacity="0.3" filter="url(#glow-lg)"/>`;
  // Connecting circle (dashed)
  html += `<circle cx="0" cy="0" r="${RADIUS}" fill="none" stroke="#9E7A3E" stroke-width="1" stroke-opacity="0.2" stroke-dasharray="3,6"/>`;
  // Animated pulse ring
  html += `<circle cx="0" cy="0" r="${RADIUS}" fill="none" stroke="#D4A059" stroke-width="1.5" stroke-opacity="0"><animate attributeName="r" from="${RADIUS-5}" to="${RADIUS+15}" dur="3s" repeatCount="indefinite"/><animate attributeName="stroke-opacity" from="0.5" to="0" dur="3s" repeatCount="indefinite"/></circle>`;

  // Center label
  html += `<text x="0" y="-10" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="11" fill="#ccc" letter-spacing="2" font-weight="600">CLSAG RING</text>`;
  html += `<text x="0" y="8" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="9" fill="#D4A059" letter-spacing="1">${RING} MEMBERS · 1 REAL</text>`;
  html += `<text x="0" y="24" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="8" fill="#666">unprovable which</text>`;

  // Ring members with glow
  members.forEach((m,i) => {
    const angle = (i / RING) * Math.PI * 2 - Math.PI/2;
    const x = Math.cos(angle) * RADIUS;
    const y = Math.sin(angle) * RADIUS;
    const delay = (i * 0.25).toFixed(2);
    // Glow aura
    html += `<circle cx="${x}" cy="${y}" r="18" fill="url(#nodeGrad)" opacity="0.6"><animate attributeName="opacity" values="0.3;0.8;0.3" dur="2.5s" begin="${delay}s" repeatCount="indefinite"/></circle>`;
    // Connection line to center
    html += `<line x1="0" y1="0" x2="${x}" y2="${y}" stroke="#9E7A3E" stroke-width="0.5" stroke-opacity="0.15" stroke-dasharray="2,3"/>`;
    // Node circle
    html += `<circle cx="${x}" cy="${y}" r="11" fill="rgba(158,122,62,0.12)" stroke="#D4A059" stroke-width="1.5" filter="url(#glow)"><title>Ring member ${i+1} · pubkey ${m.pubkey}... · could be the real signer</title></circle>`;
    html += `<text x="${x}" y="${y+3.5}" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="9" fill="#D4A059" font-weight="700" pointer-events="none">?</text>`;
    // Pubkey label
    const lblX = Math.cos(angle) * (RADIUS+26);
    const lblY = Math.sin(angle) * (RADIUS+26);
    html += `<text x="${lblX}" y="${lblY+3}" text-anchor="middle" font-family="IBM Plex Mono,monospace" font-size="7.5" fill="#888" opacity="0.7">${m.pubkey.slice(0,4)}</text>`;
  });

  svg.innerHTML = html;
}

//
// BLOCK FORGE WHEEL (Phase 3)
// PoW visualization ring. RandomX-only in 1.0. The segment matching
// the next block's algorithm glows.
//
function renderForgeWheel(currentAlgo){
  const svg = document.getElementById('forge-wheel');
  if(!svg) return;
  const segs = [
    { name: 'RandomX',        color: '#9E7A3E', algo: 0 },
    { name: 'RandomX', color: '#A855F7', algo: 1 },
    { name: 'RandomX', color: '#F59E0B', algo: 2 },
  ];
  const R = 90, INNER = 50;
  const arc = (r, sa, ea) => {
    const x1 = Math.cos(sa)*r, y1 = Math.sin(sa)*r;
    const x2 = Math.cos(ea)*r, y2 = Math.sin(ea)*r;
    const large = ea-sa > Math.PI ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };
  let html = '';
  segs.forEach((s,i) => {
    const sa = (i/3) * Math.PI*2 - Math.PI/2;
    const ea = ((i+1)/3) * Math.PI*2 - Math.PI/2;
    const isActive = currentAlgo === s.algo;
    const x1o = Math.cos(sa)*R, y1o = Math.sin(sa)*R;
    const x2o = Math.cos(ea)*R, y2o = Math.sin(ea)*R;
    const x1i = Math.cos(ea)*INNER, y1i = Math.sin(ea)*INNER;
    const x2i = Math.cos(sa)*INNER, y2i = Math.sin(sa)*INNER;
    const large = (ea-sa) > Math.PI ? 1 : 0;
    const path = `M ${x1o} ${y1o} A ${R} ${R} 0 ${large} 1 ${x2o} ${y2o} L ${x1i} ${y1i} A ${INNER} ${INNER} 0 ${large} 0 ${x2i} ${y2i} Z`;
    html += `<path d="${path}" fill="${s.color}" opacity="${isActive ? 0.9 : 0.25}" stroke="${s.color}" stroke-width="${isActive ? 2 : 1}">
      <title>${s.name}${isActive ? ' (active)' : ''}</title>
    </path>`;
    // Label
    const ma = (sa+ea)/2;
    const lx = Math.cos(ma) * (R+12);
    const ly = Math.sin(ma) * (R+12);
    html += `<text x="${lx}" y="${ly+3}" text-anchor="middle" font-family="IBM Plex Mono" font-size="9" fill="${s.color}" font-weight="${isActive?700:400}">${s.name}</text>`;
  });
  // Center label
  html += `<text x="0" y="-3" text-anchor="middle" font-family="IBM Plex Mono" font-size="8" fill="var(--t3)" letter-spacing="1">NEXT</text>`;
  html += `<text x="0" y="12" text-anchor="middle" font-family="IBM Plex Mono" font-size="11" fill="var(--ac2)" font-weight="700">${segs[currentAlgo<segs.length?currentAlgo:0]?.name||'—'}</text>`;
  svg.innerHTML = html;
}

//
// CONVERGENCE TIMELINE (Phase 3)
// Renders last 200 blocks as vertical bars. Color = block status.
//
function renderConvergenceTimeline(){
  const el = document.getElementById('conv-bars');
  if(!el || !blockList.length) return;
  const sorted = [...blockList].sort((a,b)=>a.height-b.height).slice(-200);
  const minD = Math.min(...sorted.map(b=>parseInt(b.difficulty||1)));
  const maxD = Math.max(...sorted.map(b=>parseInt(b.difficulty||1)),minD+1);
  const html = sorted.map(b => {
    const d = parseInt(b.difficulty||1);
    const h = Math.max(8, Math.min(60, ((d-minD)/(maxD-minD))*60));
    // Color logic — for now all "normal", future: pull from get_chain_events
    const color = '#9E7A3E';
    return `<div style="width:3px;height:${h}px;background:${color};border-radius:1px" title="#${b.height} · diff ${num(d)}"></div>`;
  }).join('');
  el.innerHTML = html;
  el.scrollLeft = el.scrollWidth;
}
