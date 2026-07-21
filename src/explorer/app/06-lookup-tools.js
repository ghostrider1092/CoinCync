// ── ADDRESS VALIDATOR ────────────────────────────────────────
const B58='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58decode(str){
  let n=BigInt(0);
  for(const c of str){
    const idx=B58.indexOf(c);
    if(idx<0)return null;
    n=n*BigInt(58)+BigInt(idx);
  }
  const hex=n.toString(16).padStart(140,'0');
  const bytes=[];
  for(let i=0;i<hex.length;i+=2)bytes.push(parseInt(hex.slice(i,i+2),16));
  return new Uint8Array(bytes);
}
function toHex(b){return Array.from(b).map(x=>x.toString(16).padStart(2,'0')).join('');}
async function sha256(data){
  const buf=await crypto.subtle.digest('SHA-256',data instanceof Uint8Array?data:new TextEncoder().encode(data));
  return new Uint8Array(buf);
}
async function validateAddress(){
  const addr=($('av-input')?.value||'').trim();
  const res=$('av-result');const ph=$('av-placeholder');
  if(!addr){if(res)res.style.display='none';if(ph)ph.style.display='block';return;}
  if(res)res.style.display='block';if(ph)ph.style.display='none';

  const status=$('av-status');const grid=$('av-grid');

  let prefix='',payload=null,network='',type='';
  if(addr.startsWith('tCYNC')){prefix='tCYNC';payload=b58decode(addr.slice(5));}
  else if(addr.startsWith('CYNC')){prefix='CYNC';payload=b58decode(addr.slice(4));}
  else{
    if(status){status.textContent='✗ Invalid prefix — must start with CYNC or tCYNC';status.style.background='#FEE2E2';status.style.color='#991B1B';}
    if(grid)grid.innerHTML='';return;
  }

  if(!payload||payload.length<4){
    if(status){status.textContent='✗ Invalid address — could not decode';status.style.background='#FEE2E2';status.style.color='#991B1B';}
    return;
  }

  // Verify checksum (SHA-256 as proxy for BLAKE3)
  const body=payload.slice(0,-4);const checksum=payload.slice(-4);
  const hash=await sha256(body);
  const valid=hash[0]===checksum[0]&&hash[1]===checksum[1]&&hash[2]===checksum[2]&&hash[3]===checksum[3];

  const netByte=body[0];const typeByte=body[1];
  network=netByte===0x00?'Mainnet':netByte===0x01?'Testnet':'Unknown';
  type=typeByte===0x00?'Standard':typeByte===0x01?'Subaddress':typeByte===0x02?'Integrated':'Unknown';

  const spendKey=body.length>=34?toHex(body.slice(2,34)):'—';
  const viewKey=body.length>=66?toHex(body.slice(34,66)):'—';

  if(status){
    status.textContent=valid?'✓ Valid CoinCync address — checksum verified':'⚠ Address decoded but checksum mismatch — may be invalid';
    status.style.background=valid?'var(--acb)':'#FEF3C7';
    status.style.color=valid?'var(--ac2)':'#92400E';
  }
  if(grid)grid.innerHTML=`
    <div class="dl">Prefix</div><div class="dv"><span class="badge ${prefix==='tCYNC'?'badge-amber':''}">${prefix}</span></div>
    <div class="dl">Network</div><div class="dv">${network}</div>
    <div class="dl">Type</div><div class="dv">${type}</div>
    <div class="dl">Checksum</div><div class="dv"><span class="badge ${valid?'':'badge-red'}">${valid?'✓ Valid':'✗ Mismatch'}</span></div>
    <div class="dl">Length</div><div class="dv">${body.length} bytes payload</div>
    <div class="dl">Spend pub key</div><div class="dv" style="font-size:10px;color:var(--ac2)">${spendKey}</div>
    <div class="dl">View pub key</div><div class="dv" style="font-size:10px;color:var(--t3)">${viewKey}</div>`;
}

// ── PEER EXPLORER ─────────────────────────────────────────────
async function loadPeerExp(){
  const el=$('peer-exp-body');if(!el)return;
  const d=await rpc('get_peers');
  if(!d||!d.peers||!d.peers.length){
    el.innerHTML='<div class="loading">No peers connected</div>';return;
  }
  el.innerHTML=`<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:16px">
  ${d.peers.map(p=>`
    <div class="panel" style="margin-bottom:0">
      <div style="padding:16px 20px;border-bottom:1px solid var(--b);display:flex;align-items:center;gap:10px">
        <span class="node-online"></span>
        <span style="font-family:var(--mono);font-size:13px;font-weight:600;color:var(--t)">${p.addr}</span>
        <span class="badge ${p.outbound?'badge-amber':''}" style="margin-left:auto">${p.outbound?'outbound':'inbound'}</span>
      </div>
      <div style="padding:14px 20px">
        <div class="detail-grid" style="border:none">
          <div class="dl" style="background:none;border-bottom:1px solid var(--b)">Height</div><div class="dv" style="border-bottom:1px solid var(--b);color:var(--ac2);font-weight:600">#${num(p.height)}</div>
          <div class="dl" style="background:none;border-bottom:1px solid var(--b)">Version</div><div class="dv" style="border-bottom:1px solid var(--b)">v${p.version}</div>
          <div class="dl" style="background:none;border-bottom:1px solid var(--b)">User agent</div><div class="dv" style="border-bottom:1px solid var(--b);font-size:11px">${p.user_agent||'—'}</div>
          <div class="dl" style="background:none;border-bottom:1px solid var(--b)">Bytes sent</div><div class="dv" style="border-bottom:1px solid var(--b)">${p.bytes_sent?fmtSize(p.bytes_sent):'—'}</div>
          <div class="dl" style="background:none">Bytes recv</div><div class="dv">${p.bytes_recv?fmtSize(p.bytes_recv):'—'}</div>
        </div>
      </div>
    </div>`).join('')}
  </div>`;
}

// ── RAW BLOCK VIEWER ─────────────────────────────────────────
let _rawData=null;
async function loadRawBlock(h){
  const inp=$('rb-input');
  const height=h||parseInt(inp?.value||chainHeight);
  if(!height)return;
  if(inp)inp.value=height;
  const el=$('rb-body');const title=$('rb-title');
  if(el)el.innerHTML='<div class="loading">Loading...</div>';
  if(title)title.textContent='Block #'+num(height)+' — raw data';
  const b=await rpc('get_block_by_height',[height]);
  if(!b){if(el)el.innerHTML='<div class="loading">Block not found</div>';return;}
  b.height=height;_rawData=b;
  const json=JSON.stringify(b,null,2);
  // Syntax highlight
  const highlighted=json
    .replace(/("(?:[^"\\]|\\.)*")(\s*:)/g,'<span style="color:var(--ac2)">$1</span>$2')
    .replace(/:\s*("(?:[^"\\]|\\.)*")/g,': <span style="color:#F59E0B">$1</span>')
    .replace(/:\s*(\d+)/g,': <span style="color:#60A5FA">$1</span>')
    .replace(/:\s*(true|false|null)/g,': <span style="color:#C084FC">$1</span>');
  if(el)el.innerHTML=`<pre style="white-space:pre-wrap;word-break:break-all;font-size:11.5px;line-height:1.7">${highlighted}</pre>`;
}
function copyRawBlock(){
  if(!_rawData)return;
  navigator.clipboard.writeText(JSON.stringify(_rawData,null,2)).then(()=>{
    const el=$('rb-copy');if(el){el.textContent='Copied!';setTimeout(()=>el.textContent='Copy JSON',2000);}
  });
}

// ── GITHUB ACTIVITY ──────────────────────────────────────────
async function loadGithub(){
  const commits=$('gh-commits');const repoEl=$('gh-repo');
  if(!EXPLORER_ALLOW_EXTERNAL_DEPS){
    if(commits)commits.innerHTML='<div class="loading">GitHub API is disabled in hardened explorer mode.</div>';
    if(repoEl)repoEl.innerHTML='<div class="loading">Enable with ?allow_external_deps=1 on localhost only.</div>';
    return;
  }
  try{
    const [cRes,rRes]=await Promise.all([
      fetch('https://api.github.com/repos/CyncDevelopment/Cync-Protocol/commits?per_page=15'),
      fetch('https://api.github.com/repos/CyncDevelopment/Cync-Protocol')
    ]);
    const cData=await cRes.json();const rData=await rRes.json();

    if(Array.isArray(cData)&&commits){
      commits.innerHTML='<div style="display:flex;flex-direction:column">'+
        cData.map(c=>`
          <div style="padding:14px 20px;border-bottom:1px solid var(--b);display:flex;gap:12px;align-items:flex-start">
            <img src="${c.author?.avatar_url||''}" style="width:28px;height:28px;border-radius:50%;flex-shrink:0;background:var(--s3)" onerror="this.style.display='none'"/>
            <div style="flex:1;min-width:0">
              <div style="font-size:13px;color:var(--t);margin-bottom:3px;line-height:1.4">${(c.commit?.message||'').split('\n')[0].slice(0,80)}</div>
              <div style="font-size:11px;color:var(--t3);font-family:var(--mono)">
                <span style="color:var(--ac2)">${c.author?.login||c.commit?.author?.name||'unknown'}</span>
                · ${new Date(c.commit?.author?.date).toLocaleDateString()}
                · <a href="${c.html_url}" target="_blank" style="color:var(--t3)">${(c.sha||'').slice(0,7)}</a>
              </div>
            </div>
          </div>`).join('')+'</div>';
    }else if(commits){commits.innerHTML='<div class="loading">Could not load commits — GitHub API rate limited</div>';}

    if(rData.name&&repoEl){
      repoEl.innerHTML=`
        <div class="detail-grid">
          <div class="dl">Repository</div><div class="dv"><a href="${rData.html_url}" target="_blank" style="color:var(--ac2)">${rData.full_name}</a></div>
          <div class="dl">Description</div><div class="dv" style="font-size:12px;color:var(--t2)">${rData.description||'—'}</div>
          <div class="dl">Stars</div><div class="dv"> ${rData.stargazers_count||0}</div>
          <div class="dl">Forks</div><div class="dv"> ${rData.forks_count||0}</div>
          <div class="dl">Language</div><div class="dv">${rData.language||'—'}</div>
          <div class="dl">License</div><div class="dv">${rData.license?.name||'—'}</div>
          <div class="dl">Last push</div><div class="dv">${rData.pushed_at?new Date(rData.pushed_at).toLocaleDateString():'—'}</div>
          <div class="dl">Open issues</div><div class="dv">${rData.open_issues_count||0}</div>
        </div>
        <div style="padding:12px 20px"><a href="${rData.html_url}" target="_blank" class="btn btn-primary" style="text-decoration:none;font-size:12px">View on GitHub →</a></div>`;
    }
  }catch(e){
    if(commits)commits.innerHTML='<div class="loading">GitHub API unavailable</div>';
  }
}
