let _globe=null,_globeDone=false,_globeAuto=true;
let _constellation=null;

// Two rings of glowing dots rendered with plain Canvas2D — no
// three.js, no external deps. The rings are projected with a tilt +
// perspective so the panel reads as "3D-ish" without the half-meg
// of WebGL machinery (and works regardless of whether dep loaders
// succeed). Particle colour reads var(--ac2) so the dots follow the
// user's theme. Inner ring = peer count, outer ring = recent blocks
// with an age-based fade (newest brightest, oldest dimmest).
function initConstellation(){
  if(_constellation) return;
  const canvas=document.getElementById('constellation-canvas');
  const wrap=document.getElementById('constellation-panel');
  if(!canvas||!wrap) return;
  const ctx=canvas.getContext('2d');
  if(!ctx) return;

  // Stale diagnostic overlay from previous WebGL implementation —
  // remove if it survived a hot reload.
  const oldDiag=document.getElementById('constellation-diag');
  if(oldDiag) oldDiag.remove();

  // Backing-store DPR scaling — keeps dots crisp on high-DPI displays
  // without pushing the canvas style size off the layout.
  const dpr=window.devicePixelRatio||1;
  function sizeCanvas(){
    const w=Math.max(320,wrap.clientWidth);
    const h=wrap.clientHeight||360;
    canvas.style.width=w+'px';
    canvas.style.height=h+'px';
    canvas.width=Math.round(w*dpr);
    canvas.height=Math.round(h*dpr);
    ctx.setTransform(dpr,0,0,dpr,0,0);
    return {w,h};
  }
  let dim=sizeCanvas();

  function readAccent(){
    return getComputedStyle(document.body).getPropertyValue('--ac2').trim()||'#d4a059';
  }
  // Parse #rgb / #rrggbb / rgb(...) once per accent-change so the
  // hot path can mix alpha into rgba() strings without re-parsing.
  function parseAccent(c){
    c=c.trim();
    if(c.startsWith('#')){
      let h=c.slice(1);
      if(h.length===3) h=h.split('').map(x=>x+x).join('');
      const n=parseInt(h,16);
      return {r:(n>>16)&255,g:(n>>8)&255,b:n&255};
    }
    const m=c.match(/rgba?\(([^)]+)\)/);
    if(m){
      const p=m[1].split(',').map(s=>parseFloat(s));
      return {r:p[0]||0,g:p[1]||0,b:p[2]||0};
    }
    return {r:212,g:160,b:89};
  }
  let accent=readAccent();
  let accentRGB=parseAccent(accent);

  // ── MULTI-RING ANONYMITY-SET CONSTELLATION ────────────────────
  // Four concentric rings, each backed by a distinct privacy primitive.
  // Particles have a birth/vanish lifecycle so we can animate growth
  // (new outputs fade in) and consumption (when a transaction lands,
  // the oldest decoys "puff out" — alpha to 0, scale up briefly, gone).
  //
  //   spark    (r=0.7) — Spark commitment accumulator
  //   shielded (r=1.1) — zero-knowledge shielded note tree
  //   decoys   (r=1.6) — recent block outputs available as CLSAG decoys
  //   deep     (r=2.1) — deep-history outputs (older, dimmer)
  //
  // Inner rings rotate faster than outer rings, giving the panel a
  // gear-like depth feel even before the perspective tilt.
  const RINGS = [
    { name:'spark',    r:0.7, max:48, spin:1.00, size:2.4, dim:1.00, particles:[] },
    { name:'shielded', r:1.1, max:80, spin:0.70, size:2.2, dim:0.92, particles:[] },
    { name:'decoys',   r:1.6, max:96, spin:0.45, size:2.0, dim:0.78, particles:[] },
    { name:'deep',     r:2.1, max:64, spin:0.25, size:1.7, dim:0.55, particles:[] },
  ];
  const BIRTH_MS=700;     // fade-in duration for spawned particles
  const VANISH_MS=900;    // fade-out duration for consumed particles

  // Spawn `count` new particles in `ring` with born=now so they fade
  // in. Caps at ring.max so spawn-storms don't overflow the panel.
  function spawnIn(ring,count){
    const now=performance.now();
    const aliveN=ring.particles.filter(p=>!p.vanishAt).length;
    const slack=ring.max-aliveN;
    const n=Math.min(count,Math.max(0,slack));
    for(let i=0;i<n;i++){
      ring.particles.push({
        ang:Math.random()*Math.PI*2,
        r:ring.r+(Math.random()-0.5)*0.14,
        y:(Math.random()-0.5)*0.28*(ring.r/0.7),
        bright:ring.dim*(0.7+Math.random()*0.3),
        born:now,
        vanishAt:0,
      });
    }
  }
  // Mark the `count` oldest still-alive particles in `ring` for vanish
  // animation. Older particles get consumed first, mirroring the
  // statistical intuition that older outputs are likelier to be spent.
  function vanishIn(ring,count){
    const alive=ring.particles.filter(p=>!p.vanishAt);
    if(!alive.length) return;
    alive.sort((a,b)=>a.born-b.born);
    const now=performance.now();
    for(let i=0;i<Math.min(count,alive.length);i++){
      alive[i].vanishAt=now;
    }
  }
  function fillRingTo(ring,target){
    const aliveN=ring.particles.filter(p=>!p.vanishAt).length;
    if(target>aliveN) spawnIn(ring,target-aliveN);
    else if(target<aliveN) vanishIn(ring,aliveN-target);
  }

  // ── ANONYMITY-SET DATA SOURCES ────────────────────────────────
  // sqrt scaling so small testnet pools render visibly while large
  // mainnet pools saturate gracefully (sub-linear keeps the panel
  // readable as the network grows by orders of magnitude). Falls back
  // to peers/blocks before get_privacy_stats lands.
  function scaleSqrt(v,mul,cap){
    if(!v||v<=0) return 0;
    return Math.min(cap,Math.max(1,Math.round(Math.sqrt(v)*mul)));
  }
  function sizeSpark(){
    const v=(window._privStats?.spark_accumulator_size)|0;
    if(v>0) return scaleSqrt(v,1.0,RINGS[0].max);
    const t=document.getElementById('s-peers')?.textContent||'';
    const n=parseInt(t,10);
    return isNaN(n)?0:Math.min(n,RINGS[0].max);
  }
  function sizeShielded(){
    const v=(window._privStats?.shielded_tree_size)|0;
    if(v>0) return scaleSqrt(v,1.4,RINGS[1].max);
    if(typeof blockList!=='undefined' && blockList?.length) return Math.min(blockList.length,RINGS[1].max);
    return 0;
  }
  function sizeDecoys(){
    // CLSAG decoy pool — proxied by recent block count × ~16 outputs/block
    // mapped through sqrt into the ring's particle space.
    const blocks=(typeof blockList!=='undefined' && blockList?.length)||0;
    return scaleSqrt(blocks*4,1.0,RINGS[2].max);
  }
  function sizeDeep(){
    // Deep-history pool — log-scaled with chain height so it grows
    // visibly with each ~10× height bracket without ever saturating.
    const h=(typeof blockList!=='undefined' && blockList?.[0]?.height)||0;
    if(h<=0) return 0;
    return Math.min(RINGS[3].max,Math.max(1,Math.round(Math.log2(h+2)*4)));
  }

  // Initial seed — born=0 means "already alive, skip the fade-in" so
  // the panel isn't blank for the first ~700 ms after init.
  function seedRing(ring,n){
    for(let i=0;i<n;i++){
      ring.particles.push({
        ang:(i/Math.max(1,n))*Math.PI*2+(Math.random()-0.5)*0.2,
        r:ring.r+(Math.random()-0.5)*0.14,
        y:(Math.random()-0.5)*0.28*(ring.r/0.7),
        bright:ring.dim*(0.7+Math.random()*0.3),
        born:0,
        vanishAt:0,
      });
    }
  }
  seedRing(RINGS[0], sizeSpark()||8);
  seedRing(RINGS[1], sizeShielded()||16);
  seedRing(RINGS[2], sizeDecoys()||24);
  seedRing(RINGS[3], sizeDeep()||12);

  // Caption updater — live numeric sizes under the ring label.
  function updateCaption(){
    const lbl=document.getElementById('constellation-label');
    if(!lbl) return;
    const sp=(window._privStats?.spark_accumulator_size)|0;
    const sh=(window._privStats?.shielded_tree_size)|0;
    if(sp||sh){
      lbl.textContent='Live anonymity set · Spark '+sp+' · Shielded '+sh;
    } else {
      lbl.textContent='Live anonymity set';
    }
  }
  updateCaption();

  // Camera state — tilt is the rotation around the X axis (gives the
  // ring its perspective foreshortening), spin is the auto-rotation
  // around Y, scale is the zoom factor. Drag updates tilt + spinOffset
  // when fullscreen; wheel adjusts scale.
  let tilt=0.55;        // ~32° looking down on the rings
  let spin=0;           // running rotation
  let spinOffset=0;     // user-drag offset added to spin
  let zoom=1.0;         // 1.0 = panel size; clamp 0.6..2.4 in fullscreen
  let fullscreen=false;
  let dragStart=null;

  // Project a 3D point (x,y,z) into 2D panel coords. Tilt rotates the
  // unit ring around X, then a simple perspective divide pulls far
  // dots inward + scales their radius.
  function project(x,y,z){
    const cy=Math.cos(tilt), sy=Math.sin(tilt);
    const y2=y*cy - z*sy;
    const z2=y*sy + z*cy;
    // Camera distance — larger = less perspective distortion. 4.0 is
    // a comfortable middle ground at our radii (1..2 unit rings).
    const FL=4.0;
    const persp=FL/(FL+z2);
    return {x:x*persp, y:y2*persp, depth:z2, scale:persp};
  }

  function frame(){
    if(!fullscreen) spin += 0.004; // ~14°/s clockwise
    const totalSpin=spin+spinOffset;
    const {w,h}=dim;
    const now=performance.now();
    // Clear with full transparency so body wallpaper / theme bg shows
    // through the panel naturally.
    ctx.clearRect(0,0,w,h);

    // Cull particles whose vanish animation has finished, then project
    // every alive particle from every ring with its lifecycle modifier.
    // ~280 particles max across all rings → still trivially cheap.
    const proj=[];
    for(const ring of RINGS){
      ring.particles=ring.particles.filter(p=>!p.vanishAt || (now-p.vanishAt)<VANISH_MS);
      for(const p of ring.particles){
        const a=p.ang+totalSpin*ring.spin;
        const x=Math.cos(a)*p.r;
        const z=Math.sin(a)*p.r;
        const pp=project(x,p.y,z);
        // Lifecycle modulation — alpha + scale animate over BIRTH_MS /
        // VANISH_MS. Vanishing particles "puff out": scale up while
        // alpha drops to 0. Newly-born particles grow into existence.
        let lifeA=1, lifeS=1;
        if(p.vanishAt){
          const t=(now-p.vanishAt)/VANISH_MS;
          lifeA=Math.max(0,1-t);
          lifeS=1+t*0.7;
        } else if(p.born){
          const t=Math.min(1,(now-p.born)/BIRTH_MS);
          lifeA=t;
          lifeS=0.4+0.6*t;
        }
        proj.push({p,ring,pp,lifeA,lifeS});
      }
    }
    proj.sort((a,b)=>a.pp.depth-b.pp.depth);

    const cx=w*0.5, cy=h*0.55;
    const baseUnits=Math.min(w,h)*0.20*zoom;
    const {r,g,b}=accentRGB;

    for(const {p,ring,pp,lifeA,lifeS} of proj){
      if(lifeA<=0) continue;
      const px=cx+pp.x*baseUnits;
      const py=cy+pp.y*baseUnits;
      const baseR=ring.size*pp.scale*zoom*p.bright*lifeS;
      const glowR=baseR*4.5;
      const a=p.bright*(0.6+0.4*pp.scale)*lifeA;
      const grad=ctx.createRadialGradient(px,py,0,px,py,glowR);
      grad.addColorStop(0,`rgba(${r},${g},${b},${a})`);
      grad.addColorStop(0.35,`rgba(${r},${g},${b},${a*0.45})`);
      grad.addColorStop(1,`rgba(${r},${g},${b},0)`);
      ctx.fillStyle=grad;
      ctx.beginPath();
      ctx.arc(px,py,glowR,0,Math.PI*2);
      ctx.fill();
      ctx.fillStyle=`rgba(${Math.min(255,r+40)},${Math.min(255,g+40)},${Math.min(255,b+40)},${Math.min(1,a+0.2)})`;
      ctx.beginPath();
      ctx.arc(px,py,baseR,0,Math.PI*2);
      ctx.fill();
    }

    _constellation.raf=requestAnimationFrame(frame);
  }

  // ── theme + data reactivity ─────────────────────────────────────
  // Watch <html data-theme> for theme switches and re-read --ac2 on
  // change. Cheap because the read happens at most once per swap.
  let lastTheme=document.documentElement.getAttribute('data-theme');
  const themeObs=new MutationObserver(()=>{
    const cur=document.documentElement.getAttribute('data-theme');
    if(cur===lastTheme) return;
    lastTheme=cur;
    accent=readAccent();
    accentRGB=parseAccent(accent);
  });
  themeObs.observe(document.documentElement,{attributes:true,attributeFilter:['data-theme']});

  // Live data sync — every 2.5 s. Two kinds of update:
  //   1. New-block events: when blockList[0].height advances, simulate
  //      "spent output" churn — vanish a couple particles from the
  //      decoy + deep rings, then spawn fresh ones in the decoy ring
  //      (the new block's outputs entering the active decoy pool).
  //      This is what produces the visible vanish-with-puff animation
  //      tied to actual chain progress.
  //   2. Anonymity-set size drift: each ring gradually closes to its
  //      target population via fillRingTo(), which itself spawns or
  //      vanishes through the same lifecycle so all transitions are
  //      smooth.
  let lastTarget=[sizeSpark(),sizeShielded(),sizeDecoys(),sizeDeep()];
  let lastTipHeight=(typeof blockList!=='undefined' && blockList?.[0]?.height)||0;
  const dataPoll=setInterval(()=>{
    const tip=(typeof blockList!=='undefined' && blockList?.[0]?.height)||0;
    if(tip && tip!==lastTipHeight){
      lastTipHeight=tip;
      // Spent-output churn — 1-2 vanish from decoys, 1 from deep,
      // then a couple of fresh decoy outputs spawn in. Net effect:
      // visible "consumption" wave on every block.
      vanishIn(RINGS[2], 1+Math.floor(Math.random()*2));
      vanishIn(RINGS[3], 1);
      spawnIn(RINGS[2], 1+Math.floor(Math.random()*2));
    }
    // Drift toward target sizes — covers anonymity-set growth as new
    // private commitments and shielded notes are added to the pools.
    const targets=[sizeSpark(),sizeShielded(),sizeDecoys(),sizeDeep()];
    for(let i=0;i<RINGS.length;i++){
      if(targets[i] && targets[i]!==lastTarget[i]){
        lastTarget[i]=targets[i];
        fillRingTo(RINGS[i], targets[i]);
      }
    }
    updateCaption();
  },2500);

  // Resize: recompute backing store when wrapper changes width.
  const ro=new ResizeObserver(()=>{ dim=sizeCanvas(); });
  ro.observe(wrap);

  // ── fullscreen + drag/zoom ──────────────────────────────────────
  // Fullscreen lets the user drag to tilt the rings (mouse vertical
  // = X-axis tilt; horizontal = manual spin offset) and scroll to
  // zoom. Auto-rotation continues so the rings still feel alive.
  function onPointerDown(e){
    if(!fullscreen) return;
    e.preventDefault();
    dragStart={x:e.clientX,y:e.clientY,tilt,spin:spinOffset};
    window.addEventListener('pointermove',onPointerMove);
    window.addEventListener('pointerup',onPointerUp);
  }
  function onPointerMove(e){
    if(!dragStart) return;
    const dx=e.clientX-dragStart.x;
    const dy=e.clientY-dragStart.y;
    spinOffset=dragStart.spin-dx*0.005;
    tilt=Math.max(-0.05,Math.min(1.4,dragStart.tilt+dy*0.005));
  }
  function onPointerUp(){
    dragStart=null;
    window.removeEventListener('pointermove',onPointerMove);
    window.removeEventListener('pointerup',onPointerUp);
  }
  function onWheel(e){
    if(!fullscreen) return;
    e.preventDefault();
    zoom*=1-e.deltaY*0.001;
    zoom=Math.max(0.6,Math.min(2.4,zoom));
  }
  function setFullscreen(on){
    if(on===fullscreen) return;
    fullscreen=on;
    if(on){
      wrap.classList.add('is-fullscreen');
      document.body.style.overflow='hidden';
      canvas.addEventListener('pointerdown',onPointerDown);
      canvas.addEventListener('wheel',onWheel,{passive:false});
    } else {
      wrap.classList.remove('is-fullscreen');
      document.body.style.overflow='';
      // Reset camera so resuming auto-spin starts from a sane pose.
      tilt=0.55; spinOffset=0; zoom=1.0;
      canvas.removeEventListener('pointerdown',onPointerDown);
      canvas.removeEventListener('wheel',onWheel);
    }
    setTimeout(()=>{ dim=sizeCanvas(); },50);
  }
  document.getElementById('constellation-expand')?.addEventListener('click',()=>setFullscreen(true));
  document.getElementById('constellation-close')?.addEventListener('click',()=>setFullscreen(false));
  document.addEventListener('keydown',(e)=>{ if(e.key==='Escape' && fullscreen) setFullscreen(false); });

  _constellation={raf:0,themeObs,ro,dataPoll};
  frame();
}
