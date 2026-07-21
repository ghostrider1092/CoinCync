// ── HASHRATE & BLOCK TIME CHARTS ────────────────────────────
let _hrChart=null,_btChart=null,_dhChart=null,_ddChart=null,_emChart=null;

async function loadHashrateCharts(){
  const info=await rpc('get_info');if(!info)return;
  const h=info.height;
  const blocks=[];
  for(let i=h;i>Math.max(1,h-100);i--){
    const b=await rpc('get_block_by_height',[i]);
    if(b){b.height=i;blocks.push(b);}
  }
  if(blocks.length<2)return;
  blocks.sort((a,b)=>a.height-b.height);

  // Hashrate: diff / block_time_target
  const hrData=blocks.map(b=>parseInt(b.difficulty||info.difficulty)/120);
  const btData=[];
  for(let i=1;i<blocks.length;i++){
    const dt=blocks[i].timestamp-blocks[i-1].timestamp;
    btData.push(Math.max(0,Math.min(dt,300)));
  }
  const labels=blocks.map(b=>'#'+b.height);
  const dk=document.documentElement.classList.contains('dark');
  const tc=dk?'rgba(242,240,236,0.4)':'rgba(74,72,68,0.4)';
  const gc=dk?'rgba(212,160,89,0.12)':'rgba(158,122,62,0.08)';
  const grid={color:dk?'rgba(46,44,42,0.4)':'rgba(228,225,216,0.6)'};

  // Stats
  const avg=hrData.reduce((a,b)=>a+b,0)/hrData.length;
  const peak=Math.max(...hrData);
  const recent50=hrData.slice(-50);const old50=hrData.slice(0,50);
  const r50avg=recent50.reduce((a,b)=>a+b,0)/recent50.length;
  const o50avg=old50.reduce((a,b)=>a+b,0)/old50.length;
  const trend=((r50avg-o50avg)/o50avg*100).toFixed(1);
  const set=(id,v)=>{const el=$(id);if(el)el.textContent=v;};
  set('hr-current',fmtHr(hrData[hrData.length-1]));
  set('hr-peak',fmtHr(peak));
  set('hr-avg',fmtHr(avg));
  set('hr-trend',(trend>0?'+':'')+trend+'%');
  if($('hr-trend'))$('hr-trend').style.color=trend>0?'var(--ac2)':'#EF4444';

  const opts={responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
    scales:{x:{ticks:{color:tc,font:{family:'IBM Plex Mono',size:9},maxTicksLimit:10},grid},
    y:{ticks:{color:tc,font:{family:'IBM Plex Mono',size:9}},grid}}};

  const hc=$('hashrate-chart');
  if(hc){if(_hrChart)_hrChart.destroy();
    _hrChart=new Chart(hc,{type:'line',data:{labels,datasets:[{label:'Hashrate',data:hrData,
      borderColor:'#9E7A3E',backgroundColor:gc,borderWidth:2,pointRadius:1,fill:true,tension:0.3}]},options:{...opts,scales:{...opts.scales,y:{...opts.scales.y,ticks:{...opts.scales.y.ticks,callback:v=>fmtHr(v)}}}}})}

  const bc=$('blocktime-chart');
  if(bc){if(_btChart)_btChart.destroy();
    _btChart=new Chart(bc,{type:'bar',data:{labels:labels.slice(1),datasets:[
      {label:'Block time',data:btData,backgroundColor:btData.map(v=>v<20?'#7EB87C':v<60?'#9E7A3E':v<120?'#F59E0B':'#EF4444'),borderRadius:2},
      {label:'Target',data:Array(btData.length).fill(30),borderColor:'rgba(255,255,255,0.3)',borderWidth:1,borderDash:[4,4],type:'line',pointRadius:0,fill:false}
    ]},options:opts})}

  // Difficulty predictor
  const dc=$('diff-history-chart');
  if(dc){if(_dhChart)_dhChart.destroy();
    const diffs=blocks.map(b=>parseInt(b.difficulty||info.difficulty));
    _dhChart=new Chart(dc,{type:'line',data:{labels,datasets:[{label:'Difficulty',data:diffs,
      borderColor:'#9E7A3E',backgroundColor:gc,borderWidth:2,pointRadius:1,fill:true,tension:0.3}]},
      options:{...opts,scales:{...opts.scales,y:{...opts.scales.y,ticks:{...opts.scales.y.ticks,callback:v=>num(v)}}}}})}

  // Block time distribution histogram
  const dd=$('diff-dist-chart');
  if(dd){if(_ddChart)_ddChart.destroy();
    const bins=[0,10,20,30,40,50,60,90,120,180,300];
    const counts=Array(bins.length-1).fill(0);
    btData.forEach(t=>{for(let i=0;i<bins.length-1;i++){if(t>=bins[i]&&t<bins[i+1]){counts[i]++;break;}}});
    const binLabels=bins.slice(0,-1).map((b,i)=>b+'-'+bins[i+1]+'s');
    _ddChart=new Chart(dd,{type:'bar',data:{labels:binLabels,datasets:[{label:'Blocks',data:counts,
      backgroundColor:counts.map((_,i)=>i===2?'#D4A059':'rgba(158,122,62,0.5)'),borderRadius:3}]},options:opts})}

  // Diff predictor stats
  const recent20=blocks.slice(-20);
  if(recent20.length>=2){
    const times=[];
    for(let i=1;i<recent20.length;i++)times.push(recent20[i].timestamp-recent20[i-1].timestamp);
    const avgBt=times.reduce((a,b)=>a+b,0)/times.length;
    const pctChange=((30/avgBt)-1)*100;
    const set2=(id,v)=>{const el=$(id);if(el)el.textContent=v;};
    set2('dp-diff',num(info.difficulty));
    set2('dp-avg',avgBt.toFixed(1)+'s');
    set2('dp-change',(pctChange>0?'+':'')+pctChange.toFixed(1)+'%');
    set2('dp-blocks','Continuous');
    if($('dp-change'))$('dp-change').style.color=pctChange>0?'var(--ac2)':'#EF4444';
  }
}

// ── EMISSION CALCULATOR ──────────────────────────────────────
function getReward(height){
  // Asymptotic: reward = max(0.6, (100M - supply) / 2M)
  const supply = getSupplyAt(height);
  return Math.max(0.6, (100000000 - supply) / 2000000);
}
function getSupplyAt(height){
  // Numerically integrate the asymptotic curve
  let supply=0; const step=Math.max(1,Math.floor(height/1000));
  for(let h=0;h<height;h+=step){
    const reward=Math.max(0.6,(100000000-supply)/2000000);
    supply+=reward*Math.min(step,height-h);
  }
  return Math.min(supply,100000000);
}
function calcEmission(){
  const h=parseInt($('ec-height')?.value||0);
  if(!h||h<1)return;
  const supply=getSupplyAt(h);
  const reward=getReward(h);
  const pct=(supply/100000000*100).toFixed(6);
  const era=reward<=0.6?'Tail emission':reward<=10?'Mature':'Distribution';
  const er=$('ec-result');
  if(er)er.innerHTML=`
    <div style="background:var(--acb);border:1px solid #4A3A1F;border-radius:10px;padding:18px">
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px">
        <div><div class="page-sub">Total supply at block ${num(h)}</div><div style="font-family:var(--serif);font-size:24px;color:var(--ac2);margin-top:4px">${num(Math.round(supply))} CYNC</div></div>
        <div><div class="page-sub">Block reward</div><div style="font-family:var(--serif);font-size:24px;color:var(--t);margin-top:4px">${reward} CYNC</div></div>
        <div><div class="page-sub">Emission era</div><div style="font-size:13px;font-weight:600;color:var(--t);margin-top:4px">${era}</div></div>
        <div><div class="page-sub">% of max supply</div><div style="font-size:13px;font-weight:600;color:var(--t);margin-top:4px">${pct}%</div></div>
      </div>
      <div class="bar-bg" style="margin-top:14px"><div class="bar" style="width:${Math.min(parseFloat(pct)*100,100)}%"></div></div>
    </div>`;

  // Emission chart
  const ec=$('emission-chart');
  if(ec){if(_emChart)_emChart.destroy();
    const pts=[0,500000,1050000,1500000,2100000,2500000,3150000,5000000];
    const dk=document.documentElement.classList.contains('dark');
    _emChart=new Chart(ec,{type:'line',data:{
      labels:pts.map(p=>(p/1000000).toFixed(1)+'M'),
      datasets:[
        {label:'Total supply',data:pts.map(p=>getSupplyAt(p)/1000000),borderColor:'#9E7A3E',backgroundColor:dk?'rgba(212,160,89,0.1)':'rgba(158,122,62,0.07)',borderWidth:2,fill:true,tension:0.4},
        {label:'Your block',data:pts.map(p=>p<=h?null:null).concat([]),borderColor:'transparent',pointBackgroundColor:['transparent','transparent','transparent','transparent','transparent','transparent','transparent','transparent'],type:'scatter'}
      ]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},
        scales:{x:{ticks:{color:dk?'rgba(242,240,236,0.4)':'rgba(74,72,68,0.4)',font:{family:'IBM Plex Mono',size:9}}},
        y:{ticks:{color:dk?'rgba(242,240,236,0.4)':'rgba(74,72,68,0.4)',font:{family:'IBM Plex Mono',size:9},callback:v=>v+'M CYNC'}}}}})}
}

// ── CHAIN HEALTH SCORE ───────────────────────────────────────
async function loadChainHealth(){
  const info=await rpc('get_info');if(!info)return;
  let score=0;const metrics=[];

  // 1. Sync status (20pts)
  const syncPts=info.synced?20:0;
  score+=syncPts;
  metrics.push({label:'Sync status',val:info.synced?'Synced':'Syncing',pts:syncPts,max:20,icon:'🔄',ok:info.synced});

  // 2. Peer count (20pts)
  const peers=info.peer_count||0;
  const peerPts=Math.min(20,peers*5);
  score+=peerPts;
  metrics.push({label:'Peer count',val:peers+' peers',pts:peerPts,max:20,icon:'',ok:peers>=2});

  // 3. Mempool (10pts)
  const mp=info.tx_pool_size||0;
  const mpPts=mp===0?10:mp<5?7:mp<20?3:0;
  score+=mpPts;
  metrics.push({label:'Mempool',val:mp+' txs',pts:mpPts,max:10,icon:'',ok:mp<10});

  // Load recent blocks for block-time based metrics
  const blocks=[];
  for(let h=info.height;h>Math.max(1,info.height-20);h--){
    const b=await rpc('get_block_by_height',[h]);if(b){b.height=h;blocks.push(b);}
  }
  blocks.sort((a,b)=>a.height-b.height);

  // 4. Block time variance (25pts)
  let btScore=25;
  if(blocks.length>=2){
    const times=[];for(let i=1;i<blocks.length;i++)times.push(blocks[i].timestamp-blocks[i-1].timestamp);
    const avg=times.reduce((a,b)=>a+b,0)/times.length;
    const variance=Math.abs(avg-30);
    btScore=Math.max(0,Math.round(25*(1-variance/60)));
  }
  score+=btScore;
  metrics.push({label:'Block time',val:blocks.length>=2?((blocks[blocks.length-1].timestamp-blocks[0].timestamp)/(blocks.length-1)).toFixed(1)+'s avg':'—',pts:btScore,max:25,icon:'',ok:btScore>15});

  // 5. Difficulty stability (20pts)
  let diffScore=20;
  if(blocks.length>=5){
    const diffs=blocks.map(b=>parseInt(b.difficulty||info.difficulty));
    const davg=diffs.reduce((a,b)=>a+b,0)/diffs.length;
    const dvar=Math.max(...diffs.map(d=>Math.abs(d-davg)/davg));
    diffScore=Math.max(0,Math.round(20*(1-dvar*5)));
  }
  score+=diffScore;
  metrics.push({label:'Difficulty stability',val:num(info.difficulty),pts:diffScore,max:20,icon:'🎯',ok:diffScore>12});

  // 6. Ring size (5pts)
  score+=5;
  metrics.push({label:'Ring size',val:'×11 (compliant)',pts:5,max:5,icon:'',ok:true});

  // Render
  const scoreEl=$('chain-score');const gradeEl=$('chain-grade');const barEl=$('chain-bar');
  if(scoreEl)scoreEl.textContent=score;
  if(barEl)barEl.style.width=score+'%';
  const grade=score>=90?'Excellent':score>=75?'Good':score>=60?'Fair':'Poor';
  const gradeColor=score>=90?'var(--ac2)':score>=75?'#7EB87C':score>=60?'#F59E0B':'#EF4444';
  if(gradeEl){gradeEl.textContent=grade+' health';gradeEl.style.color=gradeColor;}
  if(scoreEl)scoreEl.style.color=gradeColor;

  const grid=$('chain-metrics');
  if(grid)grid.innerHTML=metrics.map(m=>`
    <div class="panel" style="margin-bottom:0">
      <div style="padding:16px 18px">
        <div style="font-size:22px;margin-bottom:8px">${m.icon}</div>
        <div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.5px;color:var(--t3);font-family:var(--mono);margin-bottom:4px">${m.label}</div>
        <div style="font-size:18px;font-weight:600;font-family:var(--serif);color:var(--t);margin-bottom:8px">${m.val}</div>
        <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:5px">
          <span style="font-size:11px;font-family:var(--mono);color:var(--t3)">${m.pts}/${m.max} pts</span>
          <span class="badge ${m.ok?'':'badge-red'}">${m.ok?'✓ Good':'⚠ Check'}</span>
        </div>
        <div class="bar-bg"><div class="bar" style="width:${m.pts/m.max*100}%;background:${m.ok?'var(--ac2)':'#EF4444'}"></div></div>
      </div>
    </div>`).join('');
}
