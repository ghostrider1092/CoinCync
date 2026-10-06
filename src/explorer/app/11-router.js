function toggleGlobeMode(){
  if(!_globe)return;
  _globeAuto=!_globeAuto;
  _globe.controls().autoRotate=_globeAuto;
  const btn=$('globe-mode-btn');
  if(btn)btn.textContent=_globeAuto?' Pause':'▶ Spin';
}
function globeResetView(){
  if(!_globe)return;
  _globe.pointOfView({lat:39,lng:-98,altitude:2.2},1000);
  _globeAuto=true;
  _globe.controls().autoRotate=true;
  const btn=$('globe-mode-btn');if(btn)btn.textContent=' Pause';
}

// Map pages to their parent dropdown
const DROP_MAP={
  rawblock:'explorer',
  peerexp:'network',chainhealth:'network',
  hashrate:'tools',diffpredict:'tools',addrval:'tools',emissioncalc:'tools',countdown:'tools',
  github:'learn',

  blocks:'explorer',mempool:'explorer',supply:'explorer',search:'explorer',tx:'explorer',
  balancelookup:'explorer',richlist:'explorer',
  status:'network',livestream:'network',webhooks:'network',
  governance:'learn',miningtutorial:'docs',apilive:'tools',txbuilder:'tools',multisig:'tools',
  network:'network',globe:'network',health:'network',
  mining:'tools',wallet:'tools',api:'tools',apifull:'tools',
  '4thamendment':'learn'
};
function go(id){
  if(!PAGES.includes(id))id='home';
  if(!isPageEnabled(id))id='home';
  localStorage.setItem('cync-page', id);
  PAGES.forEach(p=>{
    const pg=$('page-'+p);const nb=$('nb-'+p);const mb=$('mob-'+p);
    if(pg)pg.className='page'+(p===id?' active':'');
    if(nb)nb.className=(nb.tagName==='BUTTON'?'nav-btn':'')+(p===id?' active':'');
    if(mb)mb.className='mob-btn'+(p===id?' active':'');
  });
  // Mark parent dropdown button active
  ['explorer','network','tools','learn','docs'].forEach(d=>{
    const btn=$('nb-'+d+'-drop');if(btn)btn.className='drop-btn'+(DROP_MAP[id]===d?' active':'');
  });
  if(id==='blocks'){renderAllBlocks();void ensureBlocksBackfillToGenesis();}
  if(id==='mempool'){loadMempool();}else{if(_mpAutoInterval){clearInterval(_mpAutoInterval);_mpAutoInterval=null;const cb=$('mp-auto-sync');if(cb)cb.checked=false;}}
  if(id==='network'){loadPeers();setTimeout(renderHrHistChart,300);}
  if(id==='globe'){setTimeout(()=>{initGlobe().catch(()=>{});},200);}
  if(id==='home'){
    setTimeout(()=>{try{initConstellation();}catch(_){}}, 200);
    // Kick the v1.0.10 status panel; will start its own 15s interval
    setTimeout(()=>{try{ensureV108Polling();}catch(_){}}, 100);
  }else{
    // Stop the v1.0.10 panel refresh when leaving home — no point burning RPCs.
    if(_v108Interval){clearInterval(_v108Interval);_v108Interval=null;}
  }
  if(id==='health'){
    _updateHealthProbeMeta();
    loadHealth();
  }else{
    if(_healthInterval){clearInterval(_healthInterval);_healthInterval=null;}
    if(_healthMetaInterval){clearInterval(_healthMetaInterval);_healthMetaInterval=null;}
  }
  if(id==='supply'){setTimeout(renderEmissionChart,200);setTimeout(renderAnonChart,300);loadChainEvents();}
  if(id==='soak'){loadSoakStatus();}
  if(id==='leaderboard'){loadFleetLeaderboard();}
  if(id==='privacymetrics'){setTimeout(renderPrivacyMetrics,300);}
  if(id==='anonset'){setTimeout(renderAnonSetDepth,200);}
  if(id==='reorghistory'){setTimeout(renderReorgHistory,200);}
  if(id==='mininglive'){startMiningLivePoll();}else{stopMiningLivePoll();}
  if(id==='feemarket'){setTimeout(renderFeeMarket,200);}
  if(id==='privacypools'){setTimeout(renderPrivacyPools,200);}


  if(id==='status'){setTimeout(renderVersionChart,200);renderMinersLeaderboard();}
  if(id==='apilive')updateApiParams();
  if(id==='richlist')renderRichList();
  if(id==='webhooks')renderWebhookList();
  if(id==='livestream'){renderPropagationChart();renderMempoolChart();}
  if(id==='balancelookup'){};

  // Do not auto-generate wallet material on tab open.
  // User must explicitly click Generate in dev-only mode.
  const walletOutput = $('wallet-output');
  if(id==='wallet' && walletOutput && !walletOutput.style.display.includes('block')){walletOutput.style.display='none';}
  window.scrollTo(0,0);
}

//
// TRANSACTION DETAIL VIEW
//

async function viewTx(txHash){
  if(!PAGES.includes('tx')) PAGES.push('tx');
  go('tx');
  const el=$('tx-detail');
  if(!el)return;
  el.innerHTML='<div class="loading">Loading transaction...</div>';

  let tx=await rpc('get_transaction',[txHash]);
  let isMempool=false;

  // Fallback: if not found in chain, check the mempool
  if(!tx){
    const mp=await rpc('get_mempool_transactions');
    if(mp&&mp.transactions){
      const found=mp.transactions.find(t=>t.hash===txHash);
      if(found){
        // Build a tx-like object from mempool data
        tx={
          hash:found.hash, type:found.kind||'Transfer',
          input_count:found.inputs||0, output_count:found.outputs||0,
          fee:found.fee||0, size:found.size||0, ring_size:11,
          version:1, block_height:null, block_hash:null,
          has_range_proof:true, range_proof_size:0, has_recovery:false,
          signing_hash:null, extra_size:0,
          inputs:[], outputs:[],
          privacy:{
            sender_hidden:true, receiver_hidden:true, amount_hidden:true,
            clsag_ring_sig:true, bulletproofs_plus:true,
            stealth_addresses:true, dandelion_pp:true, encrypted_memo:false,
          },
        };
        isMempool=true;
      }
    }
  }

  if(!tx){
    el.innerHTML=`<div class="bc"><a onclick="go('home')">Home</a><span>›</span>Transaction</div>
      <div class="info-box amber">Transaction not found: ${txHash.slice(0,24)}...</div>
      <div style="font-size:12px;color:var(--t3);margin-top:12px">The transaction may not exist or the tx index has not caught up yet.</div>`;
    return;
  }

  const isCoinbase = (tx.type||'').toLowerCase() === 'coinbase';
  const p = tx.privacy || {};
  const inputs = tx.inputs || [];
  const outputs = tx.outputs || [];
  const ringSize = tx.ring_size || 0;

  // Privacy score: count how many features are active
  const privacyChecks = [p.sender_hidden, p.receiver_hidden, p.amount_hidden, p.clsag_ring_sig, p.bulletproofs_plus, p.stealth_addresses, p.dandelion_pp];
  const privacyScore = privacyChecks.filter(Boolean).length;
  const privacyPct = Math.round(privacyScore / privacyChecks.length * 100);

  el.innerHTML=`
    <div class="bc"><a onclick="go('home')">Home</a><span>›</span>${isMempool?'<a onclick="go(\'mempool\')" style="cursor:pointer;color:var(--ac2)">Mempool</a>':`<a onclick="viewBlock(${tx.block_height})" style="cursor:pointer;color:var(--ac2)">Block #${num(tx.block_height||0)}</a>`}<span>›</span>Transaction</div>
    <div class="page-title" style="margin-bottom:4px">Transaction Detail</div>
    <div class="page-sub" style="margin-bottom:20px">${isMempool?'<span style="color:#F0C040;font-weight:600">Unconfirmed</span> — waiting in mempool for next block':'Fully private '+(isCoinbase?'coinbase':'transfer')+' transaction'}</div>

    <!-- Privacy Score Banner -->
    <div style="background:linear-gradient(135deg,rgba(158,122,62,.12),rgba(158,122,62,.04));border:1px solid rgba(158,122,62,.25);border-radius:12px;padding:20px 24px;margin-bottom:20px;display:flex;align-items:center;gap:20px">
      <div style="min-width:64px;height:64px;border-radius:50%;background:var(--ac2);display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:700;color:#fff;font-family:var(--serif)">${privacyPct}%</div>
      <div style="flex:1">
        <div style="font-family:var(--serif);font-size:18px;color:var(--ac2);margin-bottom:6px">Privacy Score: ${privacyScore}/${privacyChecks.length}</div>
        <div style="font-size:12px;color:var(--t2);line-height:1.6">This transaction uses ${isCoinbase?'coinbase privacy (amount visible, address hidden)':'all available privacy layers. Sender, receiver, and amount are cryptographically hidden.'}
        </div>
      </div>
    </div>

    <!-- Stats Grid -->
    <div style="display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--b);border:1px solid var(--b);border-radius:12px;overflow:hidden;margin-bottom:20px">
      <div class="stat"><div class="label">Type</div><div class="val"><span class="badge ${isCoinbase?'badge-amber':''}">${tx.type||'Transfer'}</span></div></div>
      <div class="stat"><div class="label">Ring Size</div><div class="val" style="color:var(--ac2)">${ringSize}</div><div class="sub">CLSAG decoys</div></div>
      <div class="stat"><div class="label">Fee</div><div class="val">${isCoinbase?'0':num(tx.fee||0)}</div><div class="sub">${isCoinbase?'coinbase':'atomic CYNC'}</div></div>
      <div class="stat"><div class="label">Inputs</div><div class="val">${tx.input_count||0}</div><div class="sub">ring-signed</div></div>
      <div class="stat"><div class="label">Outputs</div><div class="val">${tx.output_count||0}</div><div class="sub">stealth addresses</div></div>
      <div class="stat"><div class="label">Size</div><div class="val">${num(tx.size||0)}</div><div class="sub">bytes</div></div>
    </div>

    <div class="two-col" style="margin-bottom:20px">
      <!-- Privacy Features -->
      <div class="panel">
        <div class="panel-head">Privacy Features</div>
        <div style="padding:14px 16px;display:flex;flex-direction:column;gap:8px">
          <div style="display:flex;justify-content:space-between;padding:10px 14px;background:var(--acb);border-radius:6px">
            <span style="font-size:12px;color:var(--t2)">Sender hidden</span>
            <span class="badge">${p.sender_hidden?'✓ CLSAG ring sig':'— n/a'}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 14px;background:var(--acb);border-radius:6px">
            <span style="font-size:12px;color:var(--t2)">Receiver hidden</span>
            <span class="badge">${p.receiver_hidden?'✓ stealth address':'— n/a'}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 14px;background:var(--acb);border-radius:6px">
            <span style="font-size:12px;color:var(--t2)">Amount hidden</span>
            <span class="badge">${p.amount_hidden?'✓ Bulletproofs+':'— n/a'}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 14px;background:var(--acb);border-radius:6px">
            <span style="font-size:12px;color:var(--t2)">IP hidden</span>
            <span class="badge">${p.dandelion_pp?'✓ Dandelion++':'— n/a'}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 14px;background:var(--acb);border-radius:6px">
            <span style="font-size:12px;color:var(--t2)">Encrypted memo</span>
            <span class="badge">${p.encrypted_memo?'✓ ChaCha20+ECDH':'— none'}</span>
          </div>
          <div style="display:flex;justify-content:space-between;padding:10px 14px;background:var(--acb);border-radius:6px">
            <span style="font-size:12px;color:var(--t2)">Dead man's switch</span>
            <span class="badge">${tx.has_recovery?'✓ recovery set':'— none'}</span>
          </div>
        </div>
      </div>

      <!-- Transaction Details -->
      <div class="panel">
        <div class="panel-head">Transaction Details</div>
        <div class="detail-grid">
          <div class="dl">Hash</div><div class="dv mono" style="font-size:10px;word-break:break-all">${esc(tx.hash||txHash)} <button onclick="copyText('${hex(tx.hash||txHash)}',this)" class="btn btn-outline" style="font-size:9px;padding:1px 6px">copy</button></div>
          <div class="dl">Block</div><div class="dv">${isMempool?'<span style="color:#F0C040">Mempool (pending)</span>':`<a onclick="viewBlock(${tx.block_height})" style="color:var(--ac2);cursor:pointer">#${num(tx.block_height||0)}</a>`}</div>
          <div class="dl">Block hash</div><div class="dv mono" style="font-size:10px;word-break:break-all">${isMempool?'waiting for confirmation':tx.block_hash||'—'}</div>
          <div class="dl">Version</div><div class="dv">${tx.version||1}</div>
          <div class="dl">Signing hash</div><div class="dv mono" style="font-size:10px;word-break:break-all">${tx.signing_hash||'—'}</div>
          <div class="dl">Range proof</div><div class="dv">${tx.has_range_proof?num(tx.range_proof_size||0)+' bytes':'none (coinbase)'}</div>
          <div class="dl">Extra data</div><div class="dv">${tx.extra_size||0} bytes${tx.has_recovery?' (recovery)':''}</div>
        </div>
      </div>
    </div>

    <!-- Key Images (Inputs) -->
    ${inputs.length?`<div class="panel" style="margin-bottom:20px">
      <div class="panel-head">Inputs — Key Images (${inputs.length})</div>
      <div style="padding:0">
        ${inputs.map((inp,i)=>`<div style="padding:12px 20px;border-bottom:1px solid var(--b);display:flex;align-items:center;gap:12px">
          <span style="font-family:var(--mono);font-size:10px;color:var(--t3);min-width:28px">[${i}]</span>
          <div style="flex:1">
            <div style="font-family:var(--mono);font-size:11px;color:var(--ac2);word-break:break-all">${inp.key_image||'—'}</div>
            <div style="font-size:10px;color:var(--t3);margin-top:2px">Ring size: ${inp.ring_size||ringSize} decoys</div>
          </div>
          <span class="badge">✓ CLSAG</span>
        </div>`).join('')}
      </div>
    </div>`:''}

    <!-- Stealth Addresses (Outputs) -->
    ${outputs.length?`<div class="panel" style="margin-bottom:20px">
      <div class="panel-head">Outputs — Stealth Addresses (${outputs.length})</div>
      <div style="padding:0">
        ${outputs.map((out,i)=>`<div style="padding:12px 20px;border-bottom:1px solid var(--b)">
          <div style="display:flex;align-items:center;gap:12px;margin-bottom:6px">
            <span style="font-family:var(--mono);font-size:10px;color:var(--t3);min-width:28px">[${i}]</span>
            <div style="flex:1;font-family:var(--mono);font-size:11px;color:var(--ac2);word-break:break-all">${out.stealth_address||'—'}</div>
            <span class="badge">✓ stealth</span>
          </div>
          <div style="display:flex;gap:16px;padding-left:40px;flex-wrap:wrap">
            <span style="font-size:10px;color:var(--t3)">Amount: <span style="color:var(--t2)">encrypted</span></span>
            <span style="font-size:10px;color:var(--t3)">Commitment: <span class="mono" style="color:var(--t2)">${(out.commitment||'').slice(0,16)}...</span></span>
            <span style="font-size:10px;color:var(--t3)">View tag: <span class="mono" style="color:var(--t2)">0x${(out.view_tag||0).toString(16).padStart(2,'0')}</span></span>
            ${out.lock_height?`<span style="font-size:10px;color:var(--t3)">Lock: <span style="color:#F0C040">h=${out.lock_height}</span></span>`:''}
            ${out.has_memo?`<span style="font-size:10px;color:var(--t3)">Memo: <span style="color:var(--ac2)">encrypted</span></span>`:''}
          </div>
        </div>`).join('')}
      </div>
    </div>`:''}

    <!-- Manifesto footer -->
    <div style="text-align:center;padding:20px 0;font-size:11px;color:var(--t3);font-family:var(--mono)">
      Privacy money that requires no permission. &mdash; <a onclick="go('4thamendment')" style="color:var(--ac2);cursor:pointer">The CoinCync Manifesto</a>
    </div>
  `;
}

//
// ENHANCED SEARCH (supports block height, block hash, tx hash, asset ID)
//

// Override the existing doSearch with enhanced version
const _origDoSearch = doSearch;
doSearch = async function(){
  const q=($('nav-q').value||$('mob-q').value||'').trim();
  if(!q)return;
  go('search');
  $('sq-label').textContent='Query: '+q;
  $('search-body').innerHTML='<div class="loading">Searching...</div>';

  // 1) Block height
  if(/^\d+$/.test(q)){
    const h=parseInt(q);
    if(h>=0&&h<=chainHeight){viewBlock(h);return;}
  }

  // 2) 64-char hex: try block hash, then tx hash, then asset
  if(/^[0-9a-f]{64}$/i.test(q)){
    // Try block
    const b=await rpc('get_block',[q]);
    if(b&&b.height!=null){viewBlock(b.height);return;}

    // Try transaction
    const tx=await rpc('get_transaction',[q]);
    if(tx&&tx.hash){viewTx(q);return;}

    // Try asset
    const asset=await rpc('get_asset_info',[q]);
    if(asset&&asset.name){
      $('search-body').innerHTML=`
        <div class="info-box">
          <h3>Asset: ${esc(asset.name)}</h3>
          <div class="kv-row"><span class="kv-key">Asset ID</span><span class="kv-val mono">${esc(q)}</span></div>
          <div class="kv-row"><span class="kv-key">Precision</span><span class="kv-val">${asset.precision||0}</span></div>
          <div class="kv-row"><span class="kv-key">Supply</span><span class="kv-val">${num(asset.initial_supply||0)}</span></div>
        </div>`;
      return;
    }
  }

  $('search-body').innerHTML=`<div class="info-box amber">No results for "${esc(q)}".<br><br>
    <span style="color:var(--t3);font-size:12px">Search supports: block height (e.g. 1000), block hash (64 hex), transaction hash (64 hex), or asset ID (64 hex)</span></div>`;
};

//
