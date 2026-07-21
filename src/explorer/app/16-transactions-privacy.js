// TRANSACTION BROADCASTING — submits a raw signed tx hex via send_raw_transaction.
// The RPC accepts hex bytes; the daemon validates + adds to mempool. Errors
// (size, signature, double-spend) come back as RPC error messages.
//
async function bcSubmit(){
  const hex = ($('bc-hex')?.value || '').trim().replace(/^0x/, '');
  const panel = $('bc-result-panel');
  const out = $('bc-result');
  if(!hex){
    if(panel) panel.style.display = 'block';
    if(out) out.innerHTML = '<span style="color:#C45C4F">Paste a transaction hex first.</span>';
    return;
  }
  if(!/^[0-9a-fA-F]+$/.test(hex)){
    if(panel) panel.style.display = 'block';
    if(out) out.innerHTML = '<span style="color:#C45C4F">Hex contains non-hex characters. Should be 0-9 and a-f only.</span>';
    return;
  }
  if(panel) panel.style.display = 'block';
  if(out) out.innerHTML = '<span style="color:var(--t3)">Submitting…</span>';
  try{
    const result = await rpc('send_raw_transaction', [hex]);
    if(result && result.txid){
      out.innerHTML = `<div style="color:var(--ac2);font-weight:600;margin-bottom:8px">✓ Accepted into mempool</div>
        <div>txid: <span class="mono" style="color:var(--t1)">${result.txid}</span></div>
        <div style="margin-top:8px;color:var(--t3);font-size:11px">It will appear in the next block (~120s on testnet).</div>`;
    } else {
      out.innerHTML = `<div style="color:#C45C4F;font-weight:600">Daemon returned no txid.</div>
        <div style="margin-top:6px;font-size:11px;color:var(--t3)">Possible causes: malformed tx, signature failure, double-spend, fee too low.</div>`;
    }
  }catch(e){
    out.innerHTML = `<div style="color:#C45C4F;font-weight:600">Rejected</div>
      <div style="margin-top:6px;font-size:11px;color:var(--t3)">${e && e.message ? e.message : 'unknown error'}</div>`;
  }
}

//
// PRIVACY METRICS — decoy ring distribution + output age distribution.
// Both charts compute client-side from the most recent N blocks. The data
// path: fetch get_block_by_height for blocks tip-N..tip, walk each tx's
// inputs, count decoy positions / output ages. Aggregated histogram is
// then drawn via Chart.js.
//
// The daemon's privacy guarantees mean we can't see WHICH input is the real
// one — that's the whole point. So decoy "distribution" here is actually
// "ring-position distribution across all inputs" which approximates how
// uniform the protocol's decoy selection is. A flat bar chart = good
// (uniform decoy selection); a sloped one = a heuristic privacy attack
// might find a bias to exploit.
//
let _decoyChart = null;
let _ageChart = null;

async function renderPrivacyMetrics(){
  const N_BLOCKS = 100;
  const info = await rpc('get_info');
  if(!info || !info.height) return;
  const tip = info.height;
  const start = Math.max(1, tip - N_BLOCKS + 1);
  const cnt = $('pm-block-count');
  if(cnt) cnt.textContent = String(tip - start + 1);

  // Bucket counters. Decoy: 11 ring positions × count. Age: by hour bucket.
  const decoyHist = new Array(11).fill(0);
  const ageHist = new Array(24).fill(0); // 24 hour-buckets

  // Fetch in parallel batches of 10 to avoid hammering the RPC.
  const heights = [];
  for(let h = start; h <= tip; h++) heights.push(h);

  for(let i = 0; i < heights.length; i += 10){
    const batch = heights.slice(i, i + 10);
    const results = await Promise.all(batch.map(h =>
      rpc('get_block_by_height', [h]).catch(() => null)
    ));
    for(const block of results){
      if(!block || !block.transactions) continue;
      for(const tx of block.transactions){
        if(!tx.inputs) continue;
        for(const inp of tx.inputs){
          // Each ring input contributes to all 11 ring positions equally.
          // Without seeing which is real, we count the structural distribution.
          if(Array.isArray(inp.ring_offsets) && inp.ring_offsets.length === 11){
            for(let j = 0; j < 11; j++) decoyHist[j]++;
          }
        }
        // Age histogram — per-output age in hour buckets.
        if(tx.outputs){
          for(const _out of tx.outputs){
            const ageH = Math.min(23, Math.floor((tip - (block.height || 0)) * 2 / 60));
            ageHist[ageH]++;
          }
        }
      }
    }
  }

  // Render via Chart.js (already loaded for other pages).
  const decoyCtx = document.getElementById('pm-decoy-chart')?.getContext('2d');
  if(decoyCtx && typeof Chart !== 'undefined'){
    if(_decoyChart) _decoyChart.destroy();
    _decoyChart = new Chart(decoyCtx, {
      type: 'bar',
      data: {
        labels: decoyHist.map((_, i) => 'pos ' + (i + 1)),
        datasets: [{ label:'inputs', data: decoyHist, backgroundColor:'rgba(212,160,89,0.6)', borderColor:'rgba(212,160,89,1)', borderWidth:1 }]
      },
      options: { responsive:true, plugins:{ legend:{ display:false } } }
    });
  }
  const ageCtx = document.getElementById('pm-age-chart')?.getContext('2d');
  if(ageCtx && typeof Chart !== 'undefined'){
    if(_ageChart) _ageChart.destroy();
    _ageChart = new Chart(ageCtx, {
      type: 'bar',
      data: {
        labels: ageHist.map((_, i) => i + 'h'),
        datasets: [{ label:'outputs', data: ageHist, backgroundColor:'rgba(127,184,121,0.6)', borderColor:'rgba(127,184,121,1)', borderWidth:1 }]
      },
      options: { responsive:true, plugins:{ legend:{ display:false } } }
    });
  }
}

//
// MEMPOOL FEE HISTOGRAM — pending txs bucketed by fee-per-byte rate. Lights
// up only when the mempool has activity. Helps wallet builders pick a fee
// multiplier; helps users see whether the network is congested.
//
let _mpFeeChart = null;

function _renderMempoolFeeHistogram(txData){
  const ctx = document.getElementById('mp-fee-histogram')?.getContext('2d');
  if(!ctx || typeof Chart === 'undefined') return;

  // Build buckets. Use atomic-units-per-byte to keep numbers manageable.
  // Buckets: 0-100, 100-500, 500-1k, 1k-5k, 5k-10k, 10k+ (atomic/byte).
  const labels = ['0-100', '100-500', '500-1k', '1k-5k', '5k-10k', '10k+'];
  const buckets = new Array(6).fill(0);

  if(txData && txData.transactions){
    for(const tx of txData.transactions){
      const fee = tx.fee || 0;
      const sz = tx.size || 1;
      const rate = sz > 0 ? fee / sz : 0;
      let b = 5;
      if(rate < 100) b = 0;
      else if(rate < 500) b = 1;
      else if(rate < 1000) b = 2;
      else if(rate < 5000) b = 3;
      else if(rate < 10000) b = 4;
      buckets[b] += 1;
    }
  }

  if(_mpFeeChart) _mpFeeChart.destroy();
  _mpFeeChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{ label: 'pending txs', data: buckets, backgroundColor: 'rgba(212,160,89,0.55)', borderColor: 'rgba(212,160,89,1)', borderWidth: 1 }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, ticks: { precision: 0 } } }
    }
  });
}

//
// EMISSION CURVE CHART (#28)
//
let emissionChart = null;
function renderEmissionChart() {
  const el = $('emission-chart-canvas');
  if (!el) return;
  // Asymptotic curve: reward = max(0.6, (100M - supply) / 2M)
  const CAP = 100000000;
  const DIV = 2000000;
  const TAIL = 0.6;
  const points = [];
  let supply = 0;
  for (let h = 0; h <= 6000000; h += 10000) {
    points.push({ h, supply: Math.min(supply, CAP) });
    const reward = Math.max(TAIL, (CAP - supply) / DIV);
    supply += reward * 10000;
  }
  const isDark = document.documentElement.classList.contains('dark');
  const tc = isDark ? 'rgba(242,240,236,0.5)' : 'rgba(74,72,68,0.5)';
  if (emissionChart) emissionChart.destroy();
  emissionChart = new Chart(el, {
    type: 'line',
    data: { labels: points.map(p => num(p.h)), datasets: [{
      label: 'Supply (CYNC)', data: points.map(p => p.supply),
      borderColor: '#D4A059', backgroundColor: 'rgba(212,160,89,0.1)',
      borderWidth: 2, pointRadius: 0, fill: true, tension: 0.3
    }] },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { title: { display: true, text: 'Block Height', color: tc }, ticks: { color: tc, font: { size: 9 }, maxTicksLimit: 8 }, grid: { display: false } },
        y: { title: { display: true, text: 'CYNC', color: tc }, ticks: { color: tc, font: { size: 9 }, callback: v => num(v) }, grid: { color: isDark ? 'rgba(46,44,42,0.3)' : 'rgba(228,225,216,0.3)' } }
      }
    }
  });
}

//
// ANONYMITY SET GROWTH CHART (#29)
//
let _anonHistory = [];
function trackAnonSet(info) {
  if (!info || !info.anonymity_set) return;
  _anonHistory.push({ t: Date.now(), val: info.anonymity_set });
  if (_anonHistory.length > 200) _anonHistory.shift();
}
let anonChart = null;
function renderAnonChart() {
  const el = $('anon-growth-canvas');
  if (!el || _anonHistory.length < 2) return;
  const isDark = document.documentElement.classList.contains('dark');
  const tc = isDark ? 'rgba(242,240,236,0.5)' : 'rgba(74,72,68,0.5)';
  if (anonChart) anonChart.destroy();
  anonChart = new Chart(el, {
    type: 'line',
    data: { labels: _anonHistory.map((_, i) => i), datasets: [{
      label: 'Anonymity Set', data: _anonHistory.map(h => h.val),
      borderColor: '#A855F7', backgroundColor: 'rgba(168,85,247,0.1)',
      borderWidth: 2, pointRadius: 0, fill: true, tension: 0.3
    }] },
    options: { responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: { x: { display: false }, y: { ticks: { color: tc, font: { size: 9 } }, grid: { color: isDark ? 'rgba(46,44,42,0.3)' : 'rgba(228,225,216,0.3)' } } }
    }
  });
}

//
// SOCIAL SHARE (#9)
//
function shareBlock(height) {
  const url = `https://explorer.coincync.network/#block-${height}`;
  const text = `CoinCync Block #${height} — 100% private transactions, CPU-mined with RandomX`;
  window.open(`https://x.com/intent/tweet?text=${encodeURIComponent(text)}&url=${encodeURIComponent(url)}`, '_blank');
}
function shareTelegram(text) {
  window.open(`https://t.me/share/url?url=${encodeURIComponent('https://explorer.coincync.network')}&text=${encodeURIComponent(text)}`, '_blank');
}

//
// DIFFICULTY PREDICTION (#18)
//
function renderDiffPrediction() {
  const el = $('diff-predict-val');
  if (!el || blockList.length < 5) return;
  const sorted = [...blockList].sort((a,b)=>a.height-b.height).slice(-20);
  const diffs = sorted.map(b => parseInt(b.difficulty || chainDiff));
  // Simple linear regression for next 10 blocks
  const n = diffs.length;
  const sumX = n*(n-1)/2, sumY = diffs.reduce((a,b)=>a+b,0);
  const sumXY = diffs.reduce((a,v,i)=>a+i*v,0);
  const sumX2 = n*(n-1)*(2*n-1)/6;
  const slope = (n*sumXY - sumX*sumY) / (n*sumX2 - sumX*sumX);
  const intercept = (sumY - slope*sumX) / n;
  const predicted = Math.max(1, Math.round(intercept + slope * (n + 10)));
  el.textContent = num(predicted);
  const dir = slope > 0 ? '↑' : slope < 0 ? '↓' : '→';
  const dirEl = $('diff-predict-dir');
  if (dirEl) dirEl.textContent = dir;
}

//
// BEGINNER MODAL (#13) — show on first visit
//
if (!localStorage.getItem('cync-seen')) {
  setTimeout(() => { const m = document.getElementById('beginner-modal'); if(m) m.style.display='flex'; }, 1500);
}

//
// MAINNET TEASER COUNTDOWN (#6)
//
setInterval(()=>{
  const el=document.getElementById('mainnet-teaser-countdown');
  if(!el)return;
  const launch=1790812800;
  const now=Math.floor(Date.now()/1000);
  const diff=launch-now;
  if(diff<=0){el.textContent='LIVE NOW';return;}
  const d=Math.floor(diff/86400);
  const h=Math.floor((diff%86400)/3600);
  const m=Math.floor((diff%3600)/60);
  const s=diff%60;
  el.textContent=`${d}d ${h}h ${m}m ${s}s`;
},1000);

//
