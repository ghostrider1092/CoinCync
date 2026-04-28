import { useTheme, Card, Badge, Mono, Ico, ICONS } from "./ui";
const TYPE_COLOR = { ring:"#d4a059", shielded:"#2d8cf0", coinbase:"#F0C040" };
const EXPLORER = "https://explorer.coincync.network";

// Confirmation progress ring
function ConfRing({ confs, target=10, size=32 }) {
  const pct = Math.min(confs / target, 1);
  const r = (size-4)/2, c = size/2, circ = 2 * Math.PI * r;
  const color = pct >= 1 ? "#d4a059" : pct > 0.5 ? "#F0C040" : "#EF4444";
  return (
    <div style={{ position:"relative", width:size, height:size }}>
      <svg width={size} height={size} style={{ transform:"rotate(-90deg)" }}>
        <circle cx={c} cy={c} r={r} fill="none" stroke="#2e2c2a" strokeWidth={3}/>
        <circle cx={c} cy={c} r={r} fill="none" stroke={color} strokeWidth={3}
          strokeLinecap="round" strokeDasharray={circ} strokeDashoffset={circ*(1-pct)}
          style={{ transition:"stroke-dashoffset .5s ease" }}/>
      </svg>
      <div style={{ position:"absolute", inset:0, display:"flex", alignItems:"center",
        justifyContent:"center", fontSize:8, fontWeight:700, color, fontFamily:"monospace" }}>
        {confs}
      </div>
    </div>
  );
}

export default function TxModal({ tx, onClose }) {
  const T = useTheme();
  if (!tx) return null;
  const isOut = tx.type === "sent";
  const confs = tx.confirmations || 0;

  function copyId() {
    if (navigator.clipboard) navigator.clipboard.writeText(tx.id);
    else { const ta=document.createElement("textarea"); ta.value=tx.id; document.body.appendChild(ta); ta.select(); document.execCommand("copy"); document.body.removeChild(ta); }
  }

  function openExplorer() {
    const url = `${EXPLORER}/#tx-${tx.id}`;
    if (window.__TAURI__?.shell) window.__TAURI__.shell.open(url);
    else window.open(url, "_blank");
  }

  return (
    <div onClick={onClose} style={{ position:"fixed", inset:0, background:"rgba(0,0,0,.65)", zIndex:1000,
      display:"flex", alignItems:"center", justifyContent:"center", animation:"fadeInFast .15s" }}>
      <div onClick={e=>e.stopPropagation()} style={{ background:T.card, border:`1px solid ${T.b}`,
        borderRadius:14, width:520, maxHeight:"80vh", overflowY:"auto",
        boxShadow:`0 20px 60px ${T.shadow}`, animation:"slideUp .2s ease" }}>

        {/* Header */}
        <div style={{ padding:"18px 22px", borderBottom:`1px solid ${T.b}`,
          display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div style={{ display:"flex", alignItems:"center", gap:12 }}>
            <div style={{ width:36, height:36, borderRadius:"50%",
              background:isOut?`${T.red}18`:`${T.ac2}18`,
              display:"flex", alignItems:"center", justifyContent:"center" }}>
              <Ico d={isOut?ICONS.send:ICONS.receive} size={16} color={isOut?T.red:T.ac2}/>
            </div>
            <div>
              <div style={{ fontSize:15, fontWeight:700 }}>{isOut?"Sent":"Received"}</div>
              <div style={{ fontSize:11, color:T.t3 }}>{tx.date}</div>
            </div>
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <ConfRing confs={confs}/>
            <button onClick={onClose} style={{ background:"none", border:"none", color:T.t3, cursor:"pointer" }}>
              <Ico d={ICONS.close} size={16}/>
            </button>
          </div>
        </div>

        {/* Amount */}
        <div style={{ padding:"20px 22px", textAlign:"center", borderBottom:`1px solid ${T.b}` }}>
          <div style={{ fontFamily:T.mono, fontSize:28, fontWeight:700,
            color:isOut?T.red:T.ac2, marginBottom:4 }}>
            {isOut?"−":"+"}{parseFloat(tx.amount).toFixed(4)}
          </div>
          <div style={{ fontSize:13, color:T.t2 }}>CYNC</div>
          <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>
            {confs >= 10 ? "✓ Final (checkpointed)" : `${confs}/10 confirmations`}
          </div>
        </div>

        {/* Details */}
        <div style={{ padding:"16px 22px" }}>
          {[
            ["Transaction ID", <span style={{ display:"flex", alignItems:"center", gap:6 }}>
              <Mono size={10}>{tx.id}</Mono>
              <button onClick={copyId} title="Copy" style={{background:"none",border:"none",cursor:"pointer",color:T.t3}}><Ico d={ICONS.copy} size={11}/></button>
            </span>],
            ["Block", <Mono size={11}>#{tx.height?.toLocaleString()}</Mono>],
            ["Confirmations", <span style={{ color:confs>=10?T.ac2:T.amber, fontFamily:T.mono, fontSize:11 }}>
              {confs} {confs>=10?"(final)":"(pending)"}
            </span>],
            ["Status", <Badge label={tx.status} color={confs>=10?T.ac2:T.amber}/>],
            ["Type", <Badge label={tx.txType} color={TYPE_COLOR[tx.txType]||T.ac2}/>],
            ["Ring size", <Mono size={11}>{tx.ring>0?tx.ring+" decoys":"N/A (coinbase)"}</Mono>],
            ["Fee", <Mono size={11}>{tx.fee==="0"?"None (coinbase)":parseFloat(tx.fee).toFixed(6)+" CYNC"}</Mono>],
          ].map(([label, value]) => (
            <div key={label} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
              padding:"7px 0", borderBottom:`1px solid ${T.b}` }}>
              <div style={{ fontSize:11, color:T.t3 }}>{label}</div>
              <div style={{ fontSize:11 }}>{value}</div>
            </div>
          ))}

          {tx.memo && (
            <div style={{ marginTop:12, padding:"10px 12px", background:T.bg, borderRadius:8, border:`1px solid ${T.b}` }}>
              <div style={{ fontSize:9, color:T.t3, marginBottom:4, letterSpacing:.5, textTransform:"uppercase" }}>Encrypted Memo</div>
              <div style={{ fontSize:12, color:T.t1 }}>{tx.memo}</div>
            </div>
          )}

          {/* Explorer link */}
          <button onClick={openExplorer} style={{ marginTop:12, width:"100%", padding:"8px",
            borderRadius:8, border:`1px solid ${T.ac2}30`, background:"transparent",
            color:T.ac2, fontSize:11, fontWeight:600, cursor:"pointer",
            display:"flex", alignItems:"center", justifyContent:"center", gap:6 }}>
            <Ico d={ICONS.globe} size={13} color={T.ac2}/> View in Explorer
          </button>
        </div>
      </div>
    </div>
  );
}
