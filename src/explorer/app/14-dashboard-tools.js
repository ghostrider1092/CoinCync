// MEMPOOL FEE CHART (#24)
//
let mempoolChart = null;
async function renderMempoolChart() {
  const el = $('mempool-fee-canvas'); if (!el) return;
  const info = await rpc('get_mempool_info');
  if (!info) return;
  const isDark = document.documentElement.classList.contains('dark');
  const tc = isDark ? 'rgba(242,240,236,0.5)' : 'rgba(74,72,68,0.5)';
  // Show mempool stats as a simple gauge
  const txCount = info.size || 0;
  const totalFees = (info.total_fees || 0) / 1e12;
  const bytes = info.bytes || 0;
  if (mempoolChart) mempoolChart.destroy();
  mempoolChart = new Chart(el, {
    type: 'bar',
    data: {
      labels: ['Transactions', 'Fees (CYNC)', 'Size (KB)'],
      datasets: [{ data: [txCount, totalFees, bytes / 1024],
        backgroundColor: ['#D4A059', '#A855F7', '#F59E0B'], borderRadius: 4 }]
    },
    options: { responsive: true, maintainAspectRatio: false, indexAxis: 'y',
      plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: tc, font: { size: 9 } }, grid: { display: false } },
        y: { ticks: { color: tc, font: { size: 10, family: 'IBM Plex Mono' } }, grid: { display: false } } }
    }
  });
}

//
// BLOCK PROPAGATION TIMING (#27)
//
let _propagationData = [];
function trackPropagation(height) {
  _propagationData.push({ height, seen: Date.now() });
  if (_propagationData.length > 100) _propagationData.shift();
}
let propChart = null;
function renderPropagationChart() {
  const el = $('propagation-canvas'); if (!el || _propagationData.length < 3) return;
  const isDark = document.documentElement.classList.contains('dark');
  const tc = isDark ? 'rgba(242,240,236,0.5)' : 'rgba(74,72,68,0.5)';
  // Time between when we first see each block
  const deltas = [];
  for (let i = 1; i < _propagationData.length; i++) {
    deltas.push({ h: _propagationData[i].height, delta: (_propagationData[i].seen - _propagationData[i-1].seen) / 1000 });
  }
  if (propChart) propChart.destroy();
  propChart = new Chart(el, {
    type: 'bar', data: { labels: deltas.map(d => '#' + d.h), datasets: [{
      label: 'Seconds', data: deltas.map(d => d.delta),
      backgroundColor: deltas.map(d => d.delta <= 180 ? 'rgba(212,160,89,0.5)' : 'rgba(245,158,11,0.5)'), borderRadius: 2
    }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { x: { ticks: { color: tc, font: { size: 8 }, maxTicksLimit: 15 }, grid: { display: false } },
        y: { ticks: { color: tc, font: { size: 9 } }, grid: { color: isDark ? 'rgba(46,44,42,0.3)' : 'rgba(228,225,216,0.3)' } } }
    }
  });
}

//
// CANONICAL OUTPUT SAMPLING
//
// Explorer analytics used to call the deprecated node-selected `get_decoys`
// method. Resolve a deterministic, evenly-spaced sample from the snapshot-bound
// locator catalog instead. Each resolver call stays within the node's 256-item
// limit, and every batch is bound to the same canonical snapshot.
const EXPLORER_LOCATOR_REQUEST_LIMIT = 256;
const EXPLORER_OUTPUT_SAMPLE_MAX = 1024;

function _sameRpcValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function _sampleOutputLocators(heights, requested) {
  const buckets = [];
  let total = 0;
  let previousHeight = -1;

  for (const entry of heights || []) {
    const height = Number(entry?.height);
    const count = Number(entry?.count);
    if (!Number.isSafeInteger(height) || height < 0 || height <= previousHeight ||
        !Number.isSafeInteger(count) || count <= 0) {
      return null;
    }
    if (!Number.isSafeInteger(total + count)) return null;
    buckets.push({ height, count });
    total += count;
    previousHeight = height;
  }

  const wanted = Math.min(
    Math.max(0, Math.floor(Number(requested) || 0)),
    EXPLORER_OUTPUT_SAMPLE_MAX,
    total
  );
  if (wanted === 0) return { locators: [], total };

  const locators = [];
  let bucketIndex = 0;
  let bucketStart = 0;
  for (let i = 0; i < wanted; i++) {
    const target = Math.floor(((i + 0.5) * total) / wanted);
    while (bucketIndex < buckets.length &&
           target >= bucketStart + buckets[bucketIndex].count) {
      bucketStart += buckets[bucketIndex].count;
      bucketIndex++;
    }
    if (bucketIndex >= buckets.length) return null;
    const bucket = buckets[bucketIndex];
    locators.push({ height: bucket.height, ordinal: target - bucketStart });
  }

  return { locators, total };
}

async function loadCanonicalOutputSample(requested = 256) {
  const snapshot = await rpc('get_decoy_distribution');
  if (!snapshot || !Array.isArray(snapshot.heights)) return null;

  const sampled = _sampleOutputLocators(snapshot.heights, requested);
  if (!sampled) return null;

  const outputs = [];
  for (let start = 0; start < sampled.locators.length; start += EXPLORER_LOCATOR_REQUEST_LIMIT) {
    const chunk = sampled.locators.slice(start, start + EXPLORER_LOCATOR_REQUEST_LIMIT);
    const resolved = await rpc('get_outputs_by_locators', [
      snapshot.snapshot_height,
      snapshot.snapshot_hash,
      snapshot.policy_version,
      chunk,
    ]);
    if (!resolved ||
        resolved.snapshot_height !== snapshot.snapshot_height ||
        resolved.policy_version !== snapshot.policy_version ||
        !_sameRpcValue(resolved.snapshot_hash, snapshot.snapshot_hash) ||
        !Array.isArray(resolved.outputs) ||
        resolved.outputs.length !== chunk.length) {
      return null;
    }

    for (let i = 0; i < chunk.length; i++) {
      const expected = chunk[i];
      const output = resolved.outputs[i];
      if (!output || !output.locator ||
          Number(output.locator.height) !== expected.height ||
          Number(output.locator.ordinal) !== expected.ordinal ||
          Number(output.height) !== expected.height ||
          typeof output.public_key !== 'string' || output.public_key.length !== 64 ||
          typeof output.commitment !== 'string' || output.commitment.length !== 64) {
        return null;
      }
    }
    outputs.push(...resolved.outputs);
  }

  return { snapshot, outputs, sampled: outputs.length, total: sampled.total };
}

//
// ADDRESS BALANCE LOOKUP (#32)
//
async function lookupBalance() {
  const el = $('balance-lookup-input'); const res = $('balance-lookup-result');
  if (!el || !res) return;
  const pubkey = el.value.trim();
  if (!pubkey || pubkey.length < 16) { res.innerHTML = '<span style="color:#EF4444">Enter an output public-key prefix (hex)</span>'; return; }
  res.innerHTML = '<span style="color:var(--t3)">Sampling the canonical output catalog...</span>';
  const sample = await loadCanonicalOutputSample(1000);
  if (!sample) { res.innerHTML = '<span style="color:#EF4444">Locator RPC error or stale snapshot</span>'; return; }
  const owned = sample.outputs.filter(output => output.public_key.startsWith(pubkey.slice(0, 32)));
  if (owned.length === 0) {
    res.innerHTML = `<span style="color:var(--t3)">No matching output in this ${num(sample.sampled)}-output sample (${num(sample.total)} catalogued total). Amounts remain hidden.</span>`;
    return;
  }
  res.innerHTML = `<div style="color:var(--ac2);margin-bottom:8px">${owned.length} matching output(s) in a ${num(sample.sampled)}-output sample</div>
    <div style="font-size:10px;color:var(--t3);margin-bottom:8px">This is a public-key sample, not an address balance lookup. Amounts are hidden.</div>` +
    owned.slice(0, 20).map(output => `<div style="font-family:var(--mono);font-size:10px;padding:3px 0;border-bottom:1px solid var(--b)">
      height=${output.height} · commitment=${output.commitment.slice(0, 16)}... · <span style="color:var(--ac2)">amount: ████</span>
    </div>`).join('');
}

//
// RICH LIST (#34) — sampled output-key frequency, never balances
//
async function renderRichList() {
  const el = $('rich-list-body'); if (!el) return;
  el.innerHTML = '<div style="color:var(--t3);font-size:11px">Loading...</div>';
  const sample = await loadCanonicalOutputSample(1000);
  if (!sample) { el.innerHTML = '<div style="color:#EF4444">Locator RPC error or stale snapshot</div>'; return; }
  const counts = {};
  sample.outputs.forEach(output => {
    const key = output.public_key.slice(0, 16);
    counts[key] = (counts[key] || 0) + 1;
  });
  const sorted = Object.entries(counts).sort((a, b) => b[1] - a[1]).slice(0, 20);
  el.innerHTML = sorted.map((row, i) =>
    `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--b);font-family:var(--mono);font-size:11px">
      <span style="color:${i < 3 ? 'var(--ac2)' : 'var(--t2)'}">#${i + 1} ${row[0]}...</span>
      <span>${row[1]} sampled outputs · <span style="color:var(--ac2)">balance: ████</span></span>
    </div>`).join('') +
    `<div style="font-size:9px;color:var(--t3);margin-top:8px;text-align:center">Evenly spaced sample: ${num(sample.sampled)} of ${num(sample.total)} canonical outputs. Amounts are never exposed.</div>`;
}

//
// WEBHOOK ALERTS (#36)
//
function setupWebhook() {
  const url = $('webhook-url')?.value?.trim();
  const event = $('webhook-event')?.value || 'new_block';
  const res = $('webhook-result');
  if (!url || !url.startsWith('http')) { if (res) res.innerHTML = '<span style="color:#EF4444">Enter a valid URL</span>'; return; }
  const hooks = JSON.parse(localStorage.getItem('cync-webhooks') || '[]');
  hooks.push({ url, event, created: Date.now() });
  localStorage.setItem('cync-webhooks', JSON.stringify(hooks));
  if (res) res.innerHTML = `<span style="color:#D4A059">Webhook registered for "${event}" → ${url}</span>`;
  showToast('🔔', 'Webhook saved', event, 3000);
  renderWebhookList();
}
function renderWebhookList() {
  const el = $('webhook-list'); if (!el) return;
  const hooks = JSON.parse(localStorage.getItem('cync-webhooks') || '[]');
  if (hooks.length === 0) { el.innerHTML = '<div style="color:var(--t3);font-size:11px">No webhooks configured</div>'; return; }
  el.innerHTML = hooks.map((h, i) =>
    `<div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--b);font-family:var(--mono);font-size:10px">
      <span>${h.event} → ${h.url.slice(0, 30)}...</span>
      <button onclick="removeWebhook(${i})" style="font-size:9px;color:#EF4444;background:none;border:none;cursor:pointer">✕</button>
    </div>`).join('');
}
function removeWebhook(i) {
  const hooks = JSON.parse(localStorage.getItem('cync-webhooks') || '[]');
  hooks.splice(i, 1);
  localStorage.setItem('cync-webhooks', JSON.stringify(hooks));
  renderWebhookList();
}
// Fire webhooks when new block detected
function fireWebhooks(height) {
  const hooks = JSON.parse(localStorage.getItem('cync-webhooks') || '[]');
  hooks.filter(h => h.event === 'new_block').forEach(h => {
    fetch(h.url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ event: 'new_block', height, timestamp: Date.now() })
    }).catch(() => {});
  });
}
