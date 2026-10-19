// (Anonymity-set depth viewer removed — the shielded pool is gated off
// pending audit, so there is no live anonymity set to visualise. The page
// was dropped in the explorer shrink.)

//
// REORG HISTORY PAGE (new 2026-05-23)
//
async function renderReorgHistory(){
  const asOf = $('reorg-layers-as-of');
  if (asOf) asOf.textContent = `as of ${new Date().toLocaleTimeString()}`;

  // Pull finality info to check Layer 5 + Layer 6 status. Layer 6 is
  // dormant pre-mainnet per the CIP-009.D decision; the indicator
  // reflects that until CIP-007 activation lands.
  const finality = await rpc('get_finality_info', []);
  if (finality){
    const l5 = $('reorg-l5-status');
    if (l5){ l5.textContent = (finality.last_checkpoint_height != null) ? 'ACTIVE' : 'NO CHECKPOINTS'; }
    // Layer 6 stays DORMANT regardless of finality response (the RPC
    // doesn't surface activation state for L6 yet — by design).
  }

  // Filter chain events to reorgs.
  const events = await rpc('get_chain_events', [{limit: 200}]);
  const reorgs = Array.isArray(events) ? events.filter(e => (e.kind || e.type || '').toLowerCase().includes('reorg')) : [];

  const rowsEl = $('reorg-history-rows');
  const countEl = $('reorg-count');
  if (countEl){
    countEl.textContent = reorgs.length === 0
      ? 'no reorgs detected'
      : `${reorgs.length} reorg${reorgs.length === 1 ? '' : 's'} in the last 200 events`;
  }
  if (!rowsEl) return;
  if (reorgs.length === 0){
    rowsEl.innerHTML = `<tr><td colspan="5" style="text-align:center;color:var(--verified);padding:24px">
      ✓ No reorganizations detected. The chain has stayed canonical across every
      observed block — six-layer reorg defense is doing its job.
    </td></tr>`;
    return;
  }
  rowsEl.innerHTML = reorgs.map(r => {
    const when = r.timestamp ? new Date(r.timestamp * 1000).toLocaleString() : '—';
    const at   = r.at_height ?? r.detected_at ?? '—';
    const fork = r.fork_height ?? r.fork_point ?? '—';
    const depth = (r.depth != null) ? r.depth : (at !== '—' && fork !== '—' ? (at - fork) : '—');
    const orphaned = r.orphaned_blocks_count ?? depth;
    return `<tr>
      <td>${when}</td>
      <td><span style="font-family:var(--mono)">${at}</span></td>
      <td><span style="font-family:var(--mono)">${fork}</span></td>
      <td><span class="badge">${depth}</span></td>
      <td><span style="font-family:var(--mono)">${orphaned}</span></td>
    </tr>`;
  }).join('');
}

//
// MINING-LIVE TILE (new 2026-05-23)
//
let _miningLiveInterval = null;
let _miningLiveChart = null;
function startMiningLivePoll(){
  stopMiningLivePoll();
  renderMiningLive();
  _miningLiveInterval = setInterval(renderMiningLive, 10000);
}
function stopMiningLivePoll(){
  if (_miningLiveInterval){ clearInterval(_miningLiveInterval); _miningLiveInterval = null; }
}
async function renderMiningLive(){
  const asOf = $('mininglive-as-of');
  if (asOf) asOf.textContent = `updated ${new Date().toLocaleTimeString()}`;

  const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
  const hrHuman = (h) => {
    if (h == null || !isFinite(h)) return '—';
    if (h > 1e9) return (h/1e9).toFixed(2) + ' GH/s';
    if (h > 1e6) return (h/1e6).toFixed(2) + ' MH/s';
    if (h > 1e3) return (h/1e3).toFixed(2) + ' KH/s';
    return Math.round(h) + ' H/s';
  };

  // Derive network-wide stats from PUBLIC chain data (get_info + recent
  // block timestamps). We do NOT call get_mining_live here — that RPC
  // returns the LOCAL node's mining state, which is all zeros on a
  // non-mining node like explorer.coincync.network. Network hashrate
  // is a function of difficulty + target block time and is available
  // from any node on the network. Median block time comes from the
  // same block-range we already fetch for the histogram below.
  const info = await rpc('get_info', []);
  if (!info) return;
  const TARGET_BLOCK_TIME_S = 120;
  const difficulty = Number(info.difficulty || 0);
  // Hashrate estimate: target = difficulty * 2^256 / 2^256_max work per hash;
  // simplified across difficulty units to hashes_per_block / seconds_per_block.
  // For CoinCync's PoW (difficulty IS expected hashes per block), this is
  // simply difficulty / target_block_time. Same formula as Bitcoin's
  // `bitcoin-cli getnetworkhashps` and Monero's `get_info.target` /
  // block-time conversion.
  const networkHashrate = difficulty > 0 ? difficulty / TARGET_BLOCK_TIME_S : null;
  set('mininglive-hr',   hrHuman(networkHashrate));
  set('mininglive-diff', difficulty > 0 ? difficulty.toLocaleString() : '—');

  // Pull last 50 blocks for block-time histogram. Derived from
  // get_block_range — same surface used by the blocks page. We
  // also compute the median inter-block interval from the same
  // dataset to fill the "Recent median" tile.
  const tip = info.height;
  if (tip == null) return;
  const range = await rpc('get_block_range', [{start: Math.max(0, tip-50), end: tip}]);
  const blocks = (range && range.blocks) || [];
  const times = [];
  for (let i = 1; i < blocks.length; i++){
    const dt = (blocks[i].timestamp || 0) - (blocks[i-1].timestamp || 0);
    if (dt > 0 && dt < 1800) times.push(dt);  // discard outliers
  }
  if (times.length){
    const sorted = [...times].sort((a,b) => a-b);
    const median = sorted[Math.floor(sorted.length / 2)];
    set('mininglive-median', `${median.toFixed(1)} s`);
  } else {
    set('mininglive-median', '—');
  }
  if (!times.length || typeof Chart === 'undefined') return;
  const BINS = 14;
  const maxT = Math.max(120, ...times);
  const binSize = Math.max(5, Math.ceil(maxT / BINS));
  const labels = new Array(BINS).fill('').map((_,i) => `${i*binSize}-${(i+1)*binSize}s`);
  const buckets = new Array(BINS).fill(0);
  for (const t of times){
    buckets[Math.min(BINS-1, Math.floor(t / binSize))]++;
  }
  if (_miningLiveChart){ _miningLiveChart.destroy(); _miningLiveChart = null; }
  const canvas = $('mininglive-btime');
  if (!canvas) return;
  _miningLiveChart = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: { labels, datasets: [{
      label: 'Blocks',
      data: buckets,
      backgroundColor: 'rgba(212,160,89,0.45)',
      borderColor: 'rgba(212,160,89,1)',
      borderWidth: 1,
    }]},
    options: {
      responsive: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { title: { display: true, text: 'Inter-block interval' }, ticks: { autoSkip: true, maxTicksLimit: 10 } },
        y: { title: { display: true, text: 'Block count' }, beginAtZero: true },
      },
    },
  });
}

//
// FEE ESTIMATOR (new 2026-05-23)
//
let _feeMarketChart = null;
async function renderFeeMarket(){
  const asOf = $('feemarket-as-of');
  if (asOf) asOf.textContent = `as of ${new Date().toLocaleTimeString()}`;

  const mp = await rpc('get_mempool_transactions', [{limit: 500}]);
  const txs = Array.isArray(mp) ? mp : (mp && mp.transactions) || [];
  const fees = txs.map(t => Number(t.fee_per_byte ?? t.feerate ?? 0)).filter(f => f > 0);

  // Recommend fees from current backlog. Slow = 25th percentile, Normal =
  // median, Fast = 75th, Flash = 95th. Each label maps to a "target
  // window" the user can pick.
  fees.sort((a,b) => a-b);
  const pct = (p) => fees.length ? fees[Math.floor((fees.length - 1) * p)] : 0;
  const slow   = pct(0.25);
  const normal = pct(0.50);
  const fast   = pct(0.75);
  const flash  = pct(0.95);

  // CYNC per 1KB. Server stores fee_per_byte in atomic units; divide by 1e12 → CYNC then × 1024 bytes
  const display = (atomicPerByte) => {
    if (!atomicPerByte) return '0.00000000';
    const cyncPer1KB = (atomicPerByte * 1024) / 1e12;
    return cyncPer1KB.toFixed(8);
  };
  const set = (id, v) => { const e = $(id); if (e) e.textContent = v; };
  set('feemarket-slow',   display(slow));
  set('feemarket-normal', display(normal));
  set('feemarket-fast',   display(fast));
  set('feemarket-flash',  display(flash));

  // Histogram of fee_per_byte across mempool
  if (typeof Chart === 'undefined' || fees.length === 0) return;
  const BINS = 16;
  const maxFee = fees[fees.length - 1] || 1;
  const binSize = Math.max(1, Math.ceil(maxFee / BINS));
  const labels = new Array(BINS).fill('').map((_,i) => `${i*binSize}+`);
  const buckets = new Array(BINS).fill(0);
  for (const f of fees){
    buckets[Math.min(BINS-1, Math.floor(f / binSize))]++;
  }
  if (_feeMarketChart){ _feeMarketChart.destroy(); _feeMarketChart = null; }
  const canvas = $('feemarket-hist');
  if (!canvas) return;
  _feeMarketChart = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: { labels, datasets: [{
      label: 'Pending txs',
      data: buckets,
      backgroundColor: 'rgba(212,160,89,0.45)',
      borderColor: 'rgba(212,160,89,1)',
      borderWidth: 1,
    }]},
    options: {
      responsive: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { title: { display: true, text: 'Fee (atomic / byte)' }, ticks: { autoSkip: true, maxTicksLimit: 8 } },
        y: { title: { display: true, text: 'Tx count' }, beginAtZero: true },
      },
    },
  });
}

// (Privacy-pools page removed in the explorer shrink — the Spark /
// Shielded / MW pools are gated off pending audit, so the page showed
// inactive/zero state only.)
