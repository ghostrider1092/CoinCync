// ── SEARCH ────────────────────────────────────────────────────
async function doSearch(){
  const q=($('nav-q').value||$('mob-q').value||'').trim();
  if(!q)return;
  go('search');
  $('sq-label').textContent='Query: '+q;
  $('search-body').innerHTML='<div class="loading">Searching...</div>';
  if(/^[0-9a-f]{64}$/i.test(q)){
    const b=await rpc('get_block',[q]);
    if(b){viewBlock(b.height);return;}
  }
  if(/^\d+$/.test(q)){
    const h=parseInt(q);
    if(h>=1&&h<=chainHeight){viewBlock(h);return;}
  }
  $('search-body').innerHTML='<div class="info-box amber">⚠ No results for "'+esc(q)+'". Enter a 64-character block hash or block height number.</div>';
}

// ── MOBILE NAV ────────────────────────────────────────────────
function toggleMobile(){$('mobile-menu').classList.toggle('open');}
function closeMobile(){$('mobile-menu').classList.remove('open');}

// ── PAGE NAV ──────────────────────────────────────────────────
const PAGES=['home','blocks','block','mempool','network','globe','health','supply','4thamendment','search','tx','api','soak','broadcast','leaderboard','privacymetrics','proposals','privacy','anonset','reorghistory','compare','mininglive','feemarket','privacypools'];
const DEV_ONLY_PAGES=[];
const PUBLIC_EXPLORER_PAGES=['home','blocks','block','mempool','network','globe','health','supply','4thamendment','search','tx','api','soak','broadcast','leaderboard','privacymetrics','proposals','privacy','anonset','reorghistory','compare','mininglive','feemarket','privacypools'];
const EXPLORER_DEV_MODE=(
  new URLSearchParams(window.location.search).get('dev_explorer')==='1' &&
  IS_LOCALHOST
);
const DISABLED_EXPLORER_PAGES=EXPLORER_DEV_MODE?new Set():new Set(DEV_ONLY_PAGES);
const PUBLIC_PAGE_SET=new Set(PUBLIC_EXPLORER_PAGES);

function isPageEnabled(id){
  return !DISABLED_EXPLORER_PAGES.has(id);
}

function hidePageEntrypoints(id){
  const page=$('page-'+id);
  const navBtn=$('nb-'+id);
  const mobBtn=$('mob-'+id);
  if(page)page.style.display='none';
  if(navBtn)navBtn.style.display='none';
  if(mobBtn)mobBtn.style.display='none';
  document.querySelectorAll('.drop-menu [onclick*="go(\''+id+'\')"]').forEach(el=>{
    el.style.display='none';
  });
}

function hideNonCoreEntrypoints(){
  if(EXPLORER_DEV_MODE)return;
  document.querySelectorAll('.mobile-menu .mob-btn[onclick*="go(\'"]').forEach(el=>{
    const onclick=el.getAttribute('onclick')||'';
    const match=onclick.match(/go\('([^']+)'\)/);
    if(!match)return;
    const pageId=match[1];
    if(!PUBLIC_PAGE_SET.has(pageId)||DISABLED_EXPLORER_PAGES.has(pageId)){
      el.style.display='none';
    }
  });
  document.querySelectorAll('.drop-menu [onclick*="go(\'"]').forEach(el=>{
    const onclick=el.getAttribute('onclick')||'';
    const match=onclick.match(/go\('([^']+)'\)/);
    if(!match)return;
    const pageId=match[1];
    if(!PUBLIC_PAGE_SET.has(pageId)||DISABLED_EXPLORER_PAGES.has(pageId)){
      el.style.display='none';
    }
  });
}

function applyExplorerMode(){
  const devBanner=$('dev-mode-banner');
  if(devBanner)devBanner.style.display=EXPLORER_DEV_MODE?'block':'none';
  hideNonCoreEntrypoints();
  if(DISABLED_EXPLORER_PAGES.size===0)return;
  DISABLED_EXPLORER_PAGES.forEach(id=>hidePageEntrypoints(id));
}


// ── COUNTDOWN ───────────────────────────────────────────────
function updateCountdown(){
  const target=new Date('2026-10-01T00:00:00Z');
  const now=new Date();
  const diff=Math.max(0,target-now);
  const d=Math.floor(diff/86400000);
  const h=Math.floor((diff%86400000)/3600000);
  const m=Math.floor((diff%3600000)/60000);
  const s=Math.floor((diff%60000)/1000);
  const pad=n=>String(n).padStart(2,'0');
  const set=(id,v)=>{const el=$(id);if(el)el.textContent=v;};
  set('cd-days',d);set('cd-hours',pad(h));set('cd-mins',pad(m));set('cd-secs',pad(s));
}
setInterval(updateCountdown,1000);
updateCountdown();
