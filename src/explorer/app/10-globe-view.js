function globeGoHealth(){go("health");}

async function initGlobe(){
  if(_globeDone)return;
  const el=$('globe-el');
  const loading=$('globe-loading');
  if(!el)return;
  try {
    await ensureNetworkVizDeps();
  } catch (_e) {
    if(loading)loading.textContent='Network map unavailable (dependency load failed).';
    return;
  }
  if(typeof Globe==='undefined'){
    if(loading)loading.textContent='Globe library unavailable — try refreshing.';
    return;
  }
  try{
    const dk=document.documentElement.classList.contains('dark');
    const wrap=$('globe-wrap');
    const W=wrap?wrap.clientWidth:window.innerWidth;
    const H=Math.max(520,Math.round(W*0.56));
    el.style.width=W+'px';
    el.style.height=H+'px';
    el.style.display='block';

    // ── Star field background ────────────────────────────────
    const starCanvas=document.createElement('canvas');
    starCanvas.width=W;starCanvas.height=H;
    starCanvas.style.cssText='position:absolute;inset:0;pointer-events:none;z-index:0';
    const sc=starCanvas.getContext('2d');
    sc.fillStyle=dk?'#050810':'#c8e8f5';
    sc.fillRect(0,0,W,H);
    if(dk){
      for(let i=0;i<320;i++){
        const x=Math.random()*W,y=Math.random()*H;
        const r=Math.random()*1.2+0.2;
        const op=Math.random()*0.7+0.15;
        sc.beginPath();sc.arc(x,y,r,0,Math.PI*2);
        sc.fillStyle=`rgba(255,255,255,${op})`;sc.fill();
      }
    }
    wrap.style.position='relative';
    wrap.insertBefore(starCanvas,wrap.firstChild);

    // ── Globe textures ───────────────────────────────────────
    // Priority-ordered fallback chain.  globe.gl loads these internally;
    // we probe each one and feed the globe whichever URL actually responds.
    // jsDelivr is first — it has 99.9% uptime and proper CORS headers.
    const TEXTURE_SOURCES = {
      day: [
        '/static/vendor/three-globe/textures/earth-day.jpg',
        'https://unpkg.com/three-globe@2.31.1/example/img/earth-day.jpg',
      ],
      night: [
        '/static/vendor/three-globe/textures/earth-night.jpg',
        'https://unpkg.com/three-globe@2.31.1/example/img/earth-night.jpg',
      ],
      bump: [
        '/static/vendor/three-globe/textures/earth-topology.png',
        'https://unpkg.com/three-globe@2.31.1/example/img/earth-topology.png',
      ],
    };

    // Try each URL in order; return the first one that loads within 6s.
    function _tryTexture(urls, onSuccess) {
      let i = 0;
      function attempt() {
        if (i >= urls.length) return; // all failed — globe.gl will show blank sphere
        const img = new Image();
        img.crossOrigin = 'anonymous';
        const timer = setTimeout(() => { img.src = ''; attempt(); }, 6000);
        img.onload  = () => { clearTimeout(timer); onSuccess(urls[i]); };
        img.onerror = () => { clearTimeout(timer); i++; attempt(); };
        img.src = urls[i];
      }
      attempt();
    }

    // Start texture probes — feed the winning URL straight into the globe
    const baseUrls = dk ? TEXTURE_SOURCES.night : TEXTURE_SOURCES.day;
    _tryTexture(baseUrls, url => {
      if (_globe) _globe.globeImageUrl(url);
    });
    _tryTexture(TEXTURE_SOURCES.bump, url => {
      if (_globe) _globe.bumpImageUrl(url);
    });

    // Set initial texture immediately with jsDelivr (most likely to work)
    // so the globe isn't blank while the probe runs.
    const EARTH_DAY   = TEXTURE_SOURCES.day[0];
    const EARTH_NIGHT = TEXTURE_SOURCES.night[0];
    const EARTH_BUMP  = TEXTURE_SOURCES.bump[0];

    // ── Build globe ──────────────────────────────────────────
    const globe=Globe()(el)
      .width(W).height(H)
      .backgroundColor('rgba(0,0,0,0)')
      .showAtmosphere(true)
      .atmosphereColor(dk?'#D4A059':'#4da8da')
      .atmosphereAltitude(0.22)
      // Set the jsDelivr URL immediately so the globe renders on first frame.
      // The _tryTexture probes running above will swap in a working URL if
      // jsDelivr fails — but in practice jsDelivr works everywhere.
      .globeImageUrl(dk ? EARTH_NIGHT : EARTH_DAY)
      .bumpImageUrl(EARTH_BUMP)

      // ── Node points with larger radius ─────────────────────
      .pointsData(GNODES)
      .pointLat(d=>d.lat).pointLng(d=>d.lng)
      .pointColor(d => {
        if (d.color && !d.ip) return d.color;   // privacy overlay point
        if (d.online) return '#D4A059';   // green  – connected
        // offline: fade through orange → red based on fail count
        const severity = Math.min(d.failCount / 4, 1);
        // interpolate #F59E0B (amber) → #EF4444 (red)
        const r = Math.round(245 + (239 - 245) * severity);
        const g = Math.round(158 + (68  - 158) * severity);
        const b = Math.round(11  + (68  -  11) * severity);
        return `rgb(${r},${g},${b})`;
      })
      .pointAltitude(d => d.altitude  != null ? d.altitude  : (d.online ? 0.025 : 0.01))
      .pointRadius(d  => d.radius != null ? d.radius : (d.online ? 0.55 : 0.3))
      .pointResolution(16)

      // ── Rings / radar halos ────────────────────────────────
      .ringsData(GNODES.filter(n => n.online))
      .ringLat(d=>d.lat).ringLng(d=>d.lng)
      .ringColor(d => d.color || (t => `rgba(212,160,89,${(1-t)*0.85})`))
      .ringMaxRadius(d => d.maxRadius || 4)
      .ringPropagationSpeed(d => d.speed || 1.8)
      .ringRepeatPeriod(d => d.period || 1000)

      // ── Labels ─────────────────────────────────────────────
      .labelsData(GNODES)
      .labelLat(d=>d.lat).labelLng(d=>d.lng)
      .labelText(d=>d.label)
      .labelColor(()=>'rgba(255,255,255,0.95)')
      .labelSize(1.1).labelDotRadius(0.0).labelAltitude(0.04)
      .labelResolution(3)

      // ── Animated gradient arcs ─────────────────────────────
      .arcsData(buildLiveArcs())
      .arcStartLat(d=>d.startLat).arcStartLng(d=>d.startLng)
      .arcEndLat(d=>d.endLat).arcEndLng(d=>d.endLng)
      .arcColor(d => {
        if (d._stem) {
          // Dandelion++ stem: near-invisible grey whisper
          return ['rgba(148,163,184,0.0)', 'rgba(148,163,184,0.30)', 'rgba(148,163,184,0.0)'];
        }
        if (d.pulse) {
          // Reconnect / fluff / block-blast: bright white-green
          return ['rgba(180,255,220,0.0)', 'rgba(180,255,220,1.0)', 'rgba(180,255,220,0.0)'];
        }
        // Normal live arc: dim → bright → dim green
        return ['rgba(212,160,89,0.03)', 'rgba(212,160,89,0.75)', 'rgba(212,160,89,0.03)'];
      })
      .arcAltitude(d=>d.alt||0.35)
      .arcStroke(d => d.pulse ? 1.8 : d._stem ? 0.25 : (d.stroke || 0.5))
      .arcDashLength(0.45).arcDashGap(0.12)
      .arcDashAnimateTime(d => d.pulse ? 700 : d._stem ? 4000 : (d.speed || 1800))

      // ── Popup on click ─────────────────────────────────────
      .onPointClick(async d=>{
        const tt=$('globe-tt');
        if(!tt)return;
        // Show immediately with basic info
        tt.style.display='block';
        const dotColor = d.online ? '#D4A059' : '#EF4444';
        const dotGlow  = d.online ? '0 0 6px #D4A059' : '0 0 6px #EF4444';
        const statusTxt = d.online ? 'Online' : `Offline (${d.failCount} missed pings)`;
        tt.innerHTML=
          '<div style="font-weight:700;color:var(--t);margin-bottom:6px;font-size:13px">'+
          `<span style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${dotColor};box-shadow:${dotGlow};margin-right:6px"></span>`+
          d.label+' <span style="font-family:var(--mono);color:var(--ac2);font-size:11px">'+d.id+'</span></div>'+
          `<div style="color:${d.online ? '#D4A059' : '#EF4444'};font-size:11px;margin-bottom:4px;font-weight:600">${statusTxt}</div>`+
          '<div style="color:var(--t3);margin-bottom:4px;font-size:11px">'+d.city+'</div>'+
          '<div style="color:var(--t2);margin-bottom:10px;font-size:11px">'+d.role+'</div>'+
          '<div id="globe-node-data" style="font-size:11px;color:var(--t3);margin-bottom:8px">Fetching live data...</div>'+
          '<div onclick="globeGoHealth()" style="color:var(--ac2);cursor:pointer;font-size:11px;font-weight:600">View health dashboard →</div>';
        tt.style.left='20px';tt.style.top='20px';
        // Fly to node
        globe.pointOfView({lat:d.lat,lng:d.lng,altitude:1.4},1200);
        // Fetch live data
        try{
          // Route through the RPC variable so the network segment is
          // included AND the base URL respects the IPFS-mirror
          // `_API_BASE` picked at page load. Previously this was
          // `fetch('/api', ...)` — missing the /testnet or /mainnet
          // segment, relying on an nginx catch-all that not every
          // deploy has, AND not portable to an IPFS gateway.
          const r=await fetch(RPC,{method:'POST',headers:{'Content-Type':'application/json'},
            body:JSON.stringify({jsonrpc:'2.0',id:1,method:'get_info'})});
          const j=await r.json();
          const info=j.result;
          if(info){
            const nd=$('globe-node-data');
            if(nd)nd.innerHTML=
              '<div style="display:grid;grid-template-columns:1fr 1fr;gap:4px 12px">'+
              '<span style="color:var(--t3)">Height</span><span style="color:var(--ac2);font-weight:600">#'+Number(info.height).toLocaleString()+'</span>'+
              '<span style="color:var(--t3)">Peers</span><span style="color:var(--t)">'+info.peer_count+'</span>'+
              '<span style="color:var(--t3)">Synced</span><span style="color:var(--ac2)">'+(info.synced?'✓ Yes':'Syncing')+'</span>'+
              '<span style="color:var(--t3)">Mempool</span><span style="color:var(--t)">'+info.tx_pool_size+' txs</span>'+
              '</div>';
          }
        }catch(e){}
        setTimeout(()=>{if(tt)tt.style.display='none';},6000);
      })
      .onPointHover(d=>{el.style.cursor=d?'pointer':'default';});

    // ── Polygon overlay (subtle country borders — always on) ────
    // We keep a very faint polygon overlay for definition but NEVER
    // replace the photo texture with flat green polygons.
    setTimeout(()=>{
      // Always show photo earth.  Polygon overlay is optional extra detail.
      // We DON'T set globeImageUrl(null) — that's what caused the green earth.
      if (EXPLORER_ALLOW_EXTERNAL_DEPS && typeof d3 !== 'undefined' && typeof topojson !== 'undefined') {
        d3.json('/static/vendor/world-atlas/2/countries-110m.json').then(world=>{
          const countries=topojson.feature(world,world.objects.countries).features;
          globe
            .polygonsData(countries)
            .polygonCapColor(()=>'rgba(0,0,0,0)')        // transparent cap — texture shows through
            .polygonSideColor(()=>'rgba(255,255,255,0.04)') // barely-visible edge lines
            .polygonStrokeColor(()=>'rgba(255,255,255,0.12)')
            .polygonAltitude(0.001);
          // NOTE: globeImageUrl is intentionally NOT set here — photo earth stays
        }).catch(()=>{/* silently ignore if world-atlas unavailable */});
      }
    },3000);

    // ── Block-mined arc burst (fires from miner toward all live peers) ──────
    let _lastGlobeHeight = 0;
    setInterval(async () => {
      try {
        // Same fix as the globe tooltip above — route through the
        // resolved RPC variable so the network segment + `_API_BASE`
        // are both applied.
        const r = await fetch(RPC, {
          method: 'POST',
          headers: {'Content-Type':'application/json'},
          body: JSON.stringify({jsonrpc:'2.0', id:1, method:'get_info'}),
          signal: AbortSignal.timeout(5000),
        });
        const j = await r.json();
        const h = j?.result?.height || 0;
        if (h > _lastGlobeHeight && _lastGlobeHeight > 0) {
          // New block — blast arcs from RIC (explorer node) to all live peers
          const src = GNODES.find(n => n.label === 'RIC' && n.online);
          if (src) {
            const blastArcs = GNODES
              .filter(n => n.online && n.label !== 'RIC')
              .map(n => ({
                startLat: src.lat, startLng: src.lng,
                endLat: n.lat, endLng: n.lng,
                pulse: true,
              }));
            if (blastArcs.length) {
              globe.arcsData([...buildLiveArcs(), ...blastArcs]);
              setTimeout(() => { if (_globe) _globe.arcsData(buildLiveArcs()); }, 2000);
            }
          }
        }
        _lastGlobeHeight = h;
      } catch(_) {}
    }, 8000);

    // ── Start live node health polling ───────────────────────
    // Slight delay so globe finishes initialising first
    setTimeout(_startNodeHealthPoll, 2000);
    setTimeout(_schedulePrivacyDemo, 3000);

    // ── Controls ─────────────────────────────────────────────
    globe.controls().autoRotate=true;
    globe.controls().autoRotateSpeed=0.55;
    globe.controls().enableDamping=true;
    globe.controls().dampingFactor=0.08;
    globe.controls().minDistance=200;
    globe.controls().maxDistance=900;
    globe.controls().addEventListener('start',()=>{
      if(_globeAuto)globe.controls().autoRotate=false;
    });
    globe.controls().addEventListener('end',()=>{
      if(_globeAuto)setTimeout(()=>{if(_globeAuto)globe.controls().autoRotate=true;},3500);
    });

    // ── Fly-to animation on load ─────────────────────────────
    // Start far out showing whole earth
    globe.pointOfView({lat:20,lng:0,altitude:4},0);
    // Then fly to USA
    setTimeout(()=>{
      globe.pointOfView({lat:39,lng:-98,altitude:2.2},2500);
    },600);

    // ── Canvas fill fix ──────────────────────────────────────
    setTimeout(()=>{
      const canvas=el.querySelector('canvas');
      if(canvas){canvas.style.cssText='width:100%!important;height:100%!important;display:block';}
    },100);

    // ── Resize handler ───────────────────────────────────────
    window.addEventListener('resize',()=>{
      if(!_globe)return;
      const w2=$('globe-wrap');if(!w2)return;
      const W2=w2.clientWidth,H2=Math.max(520,Math.round(W2*0.56));
      el.style.width=W2+'px';el.style.height=H2+'px';
      _globe.width(W2).height(H2);
      starCanvas.width=W2;starCanvas.height=H2;
    });

    _globe=globe;_globeDone=true;
    if(loading)loading.style.display='none';

  }catch(err){
    console.error('Globe error:',err);
    if(loading)loading.textContent='Globe error: '+err.message;
  }
}
