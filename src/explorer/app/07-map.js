// ── WORLD MAP (D3 - replaced by Globe.gl) ───────────────────
const MNODES=[
  {n:'seed1',   id:'1a2b',lat:40.74, lng:-74.17, role:'Seed (US-East)'},
  {n:'seed2',   id:'3c4d',lat:52.37, lng:4.90,   role:'Seed (Europe)'},
  {n:'seed3',   id:'5e6f',lat:35.68, lng:139.69, role:'Seed (Asia-Pacific)'},
  {n:'explorer',id:'7a8b',lat:32.78, lng:-96.80, role:'Explorer · Monitor'},
  {n:'api',     id:'9c0d',lat:50.11, lng:8.68,   role:'Public API · Relay'},
];
let _mz=null,_ms=null,_md=false;
function initMap(){
  if(_md)return;
  const cont=$('map-container'),load=$('map-loading'),svgEl=$('world-map-svg');
  if(!cont||!svgEl||typeof d3==='undefined'||typeof topojson==='undefined')return;
  const W=cont.clientWidth||900,H=Math.max(360,Math.round(W*0.46));
  svgEl.setAttribute('viewBox','0 0 '+W+' '+H);
  svgEl.style.height=H+'px';
  // Check WebGL support
  const testCanvas=document.createElement('canvas');
  const gl=testCanvas.getContext('webgl')||testCanvas.getContext('experimental-webgl');
  if(!gl){
    if(loading)loading.innerHTML='<div style="font-family:var(--mono);font-size:12px;color:var(--t3);padding:40px;text-align:center">WebGL not supported in this browser.</div>';
    return;
  }
  const dk=document.documentElement.classList.contains('dark');
  const O=dk?'#0a0d11':'#d4eaf5',L=dk?'#1c1e1a':'#e6e2d8',B=dk?'#2a2826':'#c4c0b4';
  const U=dk?'rgba(212,160,89,0.22)':'rgba(158,122,62,0.14)';
  const NC=dk?'#D4A059':'#9E7A3E',CN=dk?'rgba(212,160,89,0.45)':'rgba(158,122,62,0.4)';
  const GR=dk?'rgba(255,255,255,0.04)':'rgba(0,0,0,0.05)';
  const LB=dk?'rgba(240,236,230,0.9)':'rgba(15,15,14,0.8)';
  const svg=d3.select(svgEl);svg.selectAll('*').remove();
  const proj=d3.geoNaturalEarth1().scale(W/6.1).translate([W/2,H/2]);
  const path=d3.geoPath().projection(proj);
  const zoom=d3.zoom().scaleExtent([0.5,18]).on('zoom',ev=>g.attr('transform',ev.transform));
  _mz=zoom;_ms=svg;
  svg.call(zoom);
  svg.append('rect').attr('width',W).attr('height',H).attr('fill',O);
  const g=svg.append('g').attr('id','mg');
  g.append('path').datum(d3.geoGraticule()()).attr('d',path).attr('fill','none').attr('stroke',GR).attr('stroke-width',0.4);
  g.append('path').datum({type:'Sphere'}).attr('d',path).attr('fill','none').attr('stroke',dk?'rgba(255,255,255,0.07)':'rgba(0,0,0,0.1)').attr('stroke-width',0.7);
  if(!EXPLORER_ALLOW_EXTERNAL_DEPS){
    if(load)load.textContent='Map unavailable in hardened mode (external atlas disabled).';
    return;
  }
  d3.json('/static/vendor/world-atlas/2/countries-110m.json').then(world=>{
    const countries=topojson.feature(world,world.objects.countries).features;
    g.selectAll('.ctry').data(countries).join('path').attr('class','ctry')
      .attr('d',path).attr('fill',L).attr('stroke',B).attr('stroke-width',0.3)
      .on('mouseover',function(){if(!this.classList.contains('usa'))d3.select(this).attr('fill',dk?'#252521':'#ddd9cf');})
      .on('mouseout',function(){if(!this.classList.contains('usa'))d3.select(this).attr('fill',L);});
    const usa=countries.find(f=>+f.id===840);
    if(usa){g.append('path').datum(usa).attr('d',path).attr('class','usa').attr('fill',U).attr('stroke',dk?'rgba(212,160,89,0.5)':'rgba(158,122,62,0.35)').attr('stroke-width',0.9);}
    g.append('path').datum(topojson.mesh(world,world.objects.countries,(a,b)=>a!==b)).attr('d',path).attr('fill','none').attr('stroke',B).attr('stroke-width',0.25);
    // Connection lines
    MNODES.forEach((a,i)=>MNODES.forEach((b,j)=>{
      if(j<=i)return;
      const pa=proj([a.lng,a.lat]),pb=proj([b.lng,b.lat]);
      if(pa&&pb)g.append('line').attr('x1',pa[0]).attr('y1',pa[1]).attr('x2',pb[0]).attr('y2',pb[1]).attr('stroke',CN).attr('stroke-width',0.8).attr('stroke-dasharray','3,3');
    }));
    // Nodes
    const tt=$('map-tooltip');
    MNODES.forEach((node,i)=>{
      const pos=proj([node.lng,node.lat]);if(!pos)return;
      [0,1].forEach(p=>{
        const r=g.append('circle').attr('cx',pos[0]).attr('cy',pos[1]).attr('r',6).attr('fill','none').attr('stroke',NC).attr('stroke-width',1.4).attr('opacity',0);
        function pulse(){r.attr('r',6).attr('opacity',0.65).transition().duration(1800).ease(d3.easeExpOut).attr('r',20).attr('opacity',0).on('end',()=>setTimeout(pulse,(i*320)+(p*850)));}
        setTimeout(pulse,(i*320)+(p*850));
      });
      g.append('circle').attr('cx',pos[0]).attr('cy',pos[1]).attr('r',6).attr('fill',NC).attr('stroke','#fff').attr('stroke-width',1.8).style('cursor','pointer')
        .on('mouseover',function(ev){
          d3.select(this).attr('r',8);
          tt.style.display='block';
          tt.innerHTML='<strong style="color:var(--t)">'+node.n+'</strong> <span style="font-family:var(--mono);color:var(--ac2);font-size:11px">'+node.id+'</span><div style="color:var(--t3);margin-top:3px">'+node.role+'</div><div style="color:var(--ac2);margin-top:5px;font-size:10px">Click → node health</div>';
          const rc=cont.getBoundingClientRect();
          const lx=ev.clientX-rc.left,ly=ev.clientY-rc.top;
          tt.style.left=(lx>W/2?lx-150+'px':lx+16+'px');tt.style.top=(ly-8)+'px';
        })
        .on('mousemove',function(ev){const rc=cont.getBoundingClientRect();const lx=ev.clientX-rc.left,ly=ev.clientY-rc.top;tt.style.left=(lx>W/2?lx-150+'px':lx+16+'px');tt.style.top=(ly-8)+'px';})
        .on('mouseout',function(){d3.select(this).attr('r',6);tt.style.display='none';})
        .on('click',()=>go('health'));
      const ox=pos[0]<W/2?-26:10, oy=node.n==='ATL'?16:node.n==='RIC'?-9:0;
      g.append('text').attr('x',pos[0]+ox).attr('y',pos[1]+oy+4).attr('font-size','9.5').attr('font-weight','700').attr('font-family','IBM Plex Mono,monospace').attr('fill',LB).text(node.n);
    });
    if(load)load.style.display='none';
    svgEl.style.display='block';
    const leg=$('map-legend'),ctr=$('map-controls');
    if(leg)leg.style.display='flex';if(ctr)ctr.style.display='flex';
    _md=true;
    const uc=proj([-97,38]);
    if(uc)svg.transition().duration(900).call(zoom.transform,d3.zoomIdentity.translate(W/2,H/2).scale(3.8).translate(-uc[0],-uc[1]));
  }).catch(e=>{if(load)load.textContent='Map unavailable — check internet connection.';});
}
function mapZoomIn(){if(_mz&&_ms)_ms.transition().duration(250).call(_mz.scaleBy,1.6);}
function mapZoomOut(){if(_mz&&_ms)_ms.transition().duration(250).call(_mz.scaleBy,0.625);}
function mapReset(){
  if(!_mz||!_ms)return;
  const c=$('map-container');const W=c?c.clientWidth:900,H=Math.max(360,Math.round(W*0.46));
  const p=d3.geoNaturalEarth1().scale(W/6.1).translate([W/2,H/2]);
  const uc=p([-97,38]);
  if(uc)_ms.transition().duration(600).call(_mz.transform,d3.zoomIdentity.translate(W/2,H/2).scale(3.8).translate(-uc[0],-uc[1]));
}
