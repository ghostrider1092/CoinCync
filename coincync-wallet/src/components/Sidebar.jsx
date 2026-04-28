import { useTheme, Ico, ICONS, CoinLogo, Badge } from "./ui";

const NAV = [
  {id:"dashboard",label:"Dashboard",icon:"dashboard"},
  {id:"send",label:"Send",icon:"send"},
  {id:"receive",label:"Receive",icon:"receive"},
  {id:"history",label:"History",icon:"history"},
  {id:"addresses",label:"Addresses",icon:"addresses"},
  {id:"mining",label:"Mining",icon:"mining"},
  {id:"keys",label:"Keys",icon:"keys"},
  {id:"constitution",label:"Constitution",icon:"constitution"},
  {id:"privacy",label:"Privacy",icon:"privacy",badge:"22"},
  {id:"audit",label:"Supply Audit",icon:"shield"},
  {id:"settings",label:"Settings",icon:"settings"},
  {id:"changelog",label:"What's New",icon:"bell",badge:"1.0.1"},
  {id:"about",label:"About",icon:"info"},
];

export default function Sidebar({ page, setPage, syncInfo, balance, peers, seedBacked, autoLockMinutes = 15, onThemeToggle, isDark, onLock }) {
  const T = useTheme();
  const synced = syncInfo.syncPct >= 99.9;
  const autoLockLabel = autoLockMinutes > 0 ? `${autoLockMinutes}m` : "Off";

  return (
    <div style={{ width:230, background:T.panel, borderRight:`1px solid ${T.b}`,
      display:"flex", flexDirection:"column", height:"100vh", flexShrink:0,
      position:"relative", zIndex:10 }}>

      {/* ── Header ─────────────────────────────────── */}
      <div style={{ padding:"20px 18px 16px", borderBottom:`1px solid ${T.b}`,
        display:"flex", alignItems:"center", gap:12 }}>
        <div style={{ position:"relative" }}>
          <CoinLogo size={34}/>
          <div style={{ position:"absolute", bottom:-1, right:-1, width:10, height:10,
            borderRadius:"50%", background:synced?T.ac2:"#F0C040",
            border:`2px solid ${T.panel}`, animation:"pulse 2s infinite" }}/>
        </div>
        <div>
          <div style={{ fontSize:15, fontWeight:700, letterSpacing:-.3 }}>CoinCync</div>
          <div style={{ fontSize:9, color:T.t3, fontFamily:T.mono, letterSpacing:.5 }}>v1.0 · testnet</div>
        </div>
      </div>

      {/* ── Seed Warning ───────────────────────────── */}
      {!seedBacked && (
        <div onClick={()=>setPage("settings")} style={{ margin:"10px 12px 0",
          background:`linear-gradient(135deg, ${T.amber}12, ${T.amber}06)`,
          border:`1px solid ${T.amber}25`, borderRadius:10,
          padding:"8px 12px", cursor:"pointer", display:"flex", alignItems:"center", gap:8,
          transition:"all .15s" }}>
          <Ico d={ICONS.warning} size={13} color={T.amber}/>
          <span style={{ fontSize:10, color:T.amber, fontWeight:600 }}>Back up seed phrase</span>
        </div>
      )}

      {/* ── Balance Card ───────────────────────────── */}
      <div style={{ margin:"12px 12px 0", borderRadius:14, padding:16,
        position:"relative", overflow:"hidden",
        background:`linear-gradient(145deg, ${isDark?"#1a1510":"#f5efe3"}, ${isDark?"#141210":"#faf7f0"})`,
        border:`1px solid ${T.ac2}15` }}>

        {/* Background decoration */}
        <div style={{ position:"absolute", right:-20, top:-20, width:100, height:100,
          borderRadius:"50%", background:T.ac2, opacity:.04, filter:"blur(20px)" }}/>
        <div style={{ position:"absolute", left:-10, bottom:-10, width:60, height:60,
          borderRadius:"50%", background:T.ac2, opacity:.03, filter:"blur(15px)" }}/>

        <div style={{ position:"relative" }}>
          <div style={{ fontSize:9, color:T.ac2, fontWeight:700, letterSpacing:1.2,
            textTransform:"uppercase", marginBottom:6 }}>Balance</div>

          <div style={{ fontFamily:T.mono, fontSize:20, fontWeight:700, color:T.t1, lineHeight:1 }}>
            {balance.total && balance.total !== "—"
              ? <>{balance.total.split(".")[0]}<span style={{ fontSize:11, fontWeight:400, color:T.t2 }}>.{(balance.total.split(".")[1]||"0000").slice(0,4)}</span></>
              : <span style={{ color:T.t3 }}>0<span style={{ fontSize:11, fontWeight:400 }}>.0000</span></span>
            }
          </div>
          <div style={{ fontSize:10, color:T.t3, marginTop:2, fontFamily:T.mono,
            letterSpacing:.5 }}>CYNC</div>

          {/* Sync bar */}
          <div style={{ marginTop:10 }}>
            <div style={{ display:"flex", justifyContent:"space-between", marginBottom:3 }}>
              <span style={{ fontSize:9, color:T.t3 }}>{synced?"Synced":"Syncing..."}</span>
              <span style={{ fontSize:9, fontFamily:T.mono,
                color:synced?T.ac2:T.amber }}>
                {syncInfo.syncPct?.toFixed(1)||"0.0"}%
              </span>
            </div>
            <div style={{ height:3, background:`${T.b}80`, borderRadius:2 }}>
              <div style={{ height:"100%", width:`${Math.min(syncInfo.syncPct||0,100)}%`,
                background:`linear-gradient(90deg, ${T.ac2}, ${T.ac})`,
                borderRadius:2, transition:"width .8s ease" }}/>
            </div>
            <div style={{ fontSize:9, color:T.t3, marginTop:3, fontFamily:T.mono }}>
              {syncInfo.height?.toLocaleString()||"—"} / {syncInfo.chainHeight?.toLocaleString()||"—"}
            </div>
          </div>

          {/* Quick actions */}
          <div style={{ display:"flex", gap:8, marginTop:12 }}>
            <button onClick={()=>setPage("send")} style={{ flex:1,
              background:`linear-gradient(135deg, ${T.ac2}, ${T.ac})`, color:"#fff",
              border:"none", borderRadius:8, padding:"7px 0", fontSize:11, fontWeight:700,
              cursor:"pointer", boxShadow:`0 2px 8px ${T.ac2}30`, transition:"all .15s" }}>
              Send
            </button>
            <button onClick={()=>setPage("receive")} style={{ flex:1,
              background:"transparent", color:T.ac2,
              border:`1px solid ${T.ac2}30`, borderRadius:8, padding:"7px 0",
              fontSize:11, fontWeight:600, cursor:"pointer", transition:"all .15s" }}>
              Receive
            </button>
          </div>
        </div>
      </div>

      {/* ── Motto ──────────────────────────────────── */}
      <div style={{ padding:"8px 16px", textAlign:"center" }}>
        <div style={{ fontFamily:T.serif, fontSize:10, fontStyle:"italic",
          color:T.t3, lineHeight:1.4, opacity:.7 }}>
          Private by law. Private by math.
        </div>
      </div>

      {/* ── Navigation ─────────────────────────────── */}
      <nav style={{ flex:1, overflowY:"auto", padding:"0 8px 4px" }}>
        {NAV.map(n => {
          const active = page === n.id;
          return (
            <button key={n.id} onClick={()=>setPage(n.id)} style={{
              display:"flex", alignItems:"center", gap:10, width:"100%",
              padding:"9px 12px", borderRadius:10, border:"none",
              background: active ? `linear-gradient(135deg, ${T.ac2}14, ${T.ac2}08)` : "transparent",
              color: active ? T.ac2 : T.t2,
              fontSize:12, fontWeight: active ? 600 : 400,
              cursor:"pointer", marginBottom:1, transition:"all .15s",
              borderLeft: active ? `3px solid ${T.ac2}` : "3px solid transparent",
            }}
              onMouseEnter={e=>{if(!active){e.currentTarget.style.background=`${T.ac2}08`;e.currentTarget.style.color=T.t1;}}}
              onMouseLeave={e=>{if(!active){e.currentTarget.style.background="transparent";e.currentTarget.style.color=T.t2;}}}>
              <Ico d={ICONS[n.icon]||ICONS.dashboard} size={15}
                color={active?T.ac2:T.t3}/>
              {n.label}
              {n.badge && <span style={{ marginLeft:"auto",
                background:`${T.ac2}18`, color:T.ac2,
                borderRadius:12, padding:"1px 7px", fontSize:9, fontWeight:700 }}>
                {n.badge}
              </span>}
            </button>
          );
        })}
      </nav>

      {/* ── Status Bar ─────────────────────────────── */}
      <div style={{ padding:"12px 14px", borderTop:`1px solid ${T.b}`,
        background:`${T.panel}f0` }}>
        <div style={{ display:"flex", justifyContent:"space-between",
          alignItems:"center", marginBottom:4 }}>
          <div style={{ display:"flex", alignItems:"center", gap:6 }}>
            <div style={{ width:7, height:7, borderRadius:"50%",
              background:synced?T.green:T.amber,
              boxShadow:synced?`0 0 6px ${T.green}60`:`0 0 6px ${T.amber}60`,
              animation:"pulse 2s infinite" }}/>
            <span style={{ fontSize:10, color:T.t2, fontWeight:500 }}>
              {synced?"Connected":"Syncing"}
            </span>
          </div>
          <span style={{ fontSize:10, fontFamily:T.mono, color:T.t3 }}>
            {peers.peers||0} peers
          </span>
        </div>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div style={{ fontSize:9, fontFamily:T.mono, color:T.t3 }}>
            Block #{syncInfo.height?.toLocaleString()||"—"}
          </div>
          <div style={{ fontSize:9, fontFamily:T.mono, color:T.t3 }}>
            Auto-lock: {autoLockLabel}
          </div>
          <div style={{ display:"flex", gap:4 }}>
            <button onClick={onLock} title="Lock wallet (Ctrl+L)"
              style={{ background:`${T.red}15`, border:"none",
                borderRadius:8, padding:"4px 8px", cursor:"pointer",
                display:"flex", alignItems:"center", gap:4, transition:"all .15s" }}>
              <Ico d={ICONS.lock} size={10} color={T.red}/>
              <span style={{ fontSize:9, color:T.red, fontWeight:500 }}>Lock</span>
            </button>
            <button onClick={onThemeToggle} title={isDark?"Light mode":"Dark mode"}
              style={{ background:`${T.b}80`, border:"none",
                borderRadius:8, padding:"4px 8px", cursor:"pointer",
                display:"flex", alignItems:"center", gap:4, transition:"all .15s" }}>
              <Ico d={isDark?ICONS.sun:ICONS.moon} size={10} color={T.t3}/>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
