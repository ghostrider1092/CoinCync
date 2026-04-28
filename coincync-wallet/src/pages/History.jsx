import { useState, useContext } from "react";
import { useTheme, Card, Badge, Btn, Ico, ICONS, EmptyState } from "../components/ui";
import TxModal from "../components/TxModal";
import { WalletCtx } from "../App";
export default function History() {
  const T = useTheme();
  const { txs } = useContext(WalletCtx);
  const [search, setSearch]   = useState("");
  const [filter, setFilter]   = useState("all");
  const [typeFilter, setType] = useState("all");
  const [selectedTx, setSelectedTx] = useState(null);
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo]   = useState("");

  const filtered = txs.filter(tx => {
    if (filter !== "all" && tx.type !== filter) return false;
    if (typeFilter !== "all" && tx.txType !== typeFilter) return false;
    if (search && !tx.id.includes(search) && !tx.amount.includes(search) && !(tx.memo||"").includes(search)) return false;
    return true;
  });

  function exportCSV() {
    const rows = [["txid","type","amount","date","height","txtype","fee","memo"],
      ...filtered.map(t=>[t.id,t.type,t.amount,t.date,t.height,t.txType,t.fee,t.memo])];
    const csv = rows.map(r=>r.join(",")).join("\n");
    const a = document.createElement("a"); a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
    a.download = "coincync_history.csv"; a.click();
  }

  return (
    <div style={{animation:"fadeIn .2s ease"}}>
      <div style={{display:"flex",justifyContent:"space-between",alignItems:"flex-start",marginBottom:18}}>
        <div><h1 style={{fontSize:21,fontWeight:700}}>History</h1><p style={{fontSize:11,color:T.t3,marginTop:3}}>{txs.length} transactions</p></div>
        <Btn variant="ghost" small onClick={exportCSV}><Ico d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" size={13} color={T.teal}/>Export CSV</Btn>
      </div>
      <Card style={{marginBottom:12,padding:"14px 16px"}}>
        <div style={{display:"flex",gap:8,flexWrap:"wrap",alignItems:"center"}}>
          <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search txid, amount, memo..."
            style={{background:T.inputBg,border:`1px solid ${T.b}`,borderRadius:7,color:T.t1,fontSize:12,padding:"7px 11px",width:220,outline:"none"}}/>
          <div style={{display:"flex",gap:5}}>
            {["all","received","sent"].map(f=>(
              <button key={f} onClick={()=>setFilter(f)} style={{padding:"6px 10px",borderRadius:7,cursor:"pointer",border:`1px solid ${filter===f?T.teal:T.b}`,background:filter===f?`${T.teal}09`:T.bg,fontSize:11,fontWeight:600,color:filter===f?T.teal:T.t2,textTransform:"capitalize"}}>{f}</button>
            ))}
          </div>
          <div style={{display:"flex",gap:5}}>
            {["all","ring","shielded","coinbase"].map(t=>(
              <button key={t} onClick={()=>setType(t)} style={{padding:"6px 10px",borderRadius:7,cursor:"pointer",border:`1px solid ${typeFilter===t?T.blue:T.b}`,background:typeFilter===t?`${T.blue}09`:T.bg,fontSize:11,fontWeight:600,color:typeFilter===t?T.blue:T.t2,textTransform:"capitalize"}}>{t}</button>
            ))}
          </div>
        </div>
      </Card>
      <div style={{background:T.card,border:`1px solid ${T.b}`,borderRadius:11,overflow:"hidden"}}>
        <div style={{display:"grid",gridTemplateColumns:"2fr 150px 70px 75px",padding:"8px 16px",borderBottom:`1px solid ${T.b}`,fontSize:9,fontWeight:700,color:T.t3,letterSpacing:.6,textTransform:"uppercase"}}>
          <span>Transaction</span><span>Amount</span><span>Date</span><span>Type</span>
        </div>
        {filtered.length===0&&<EmptyState icon={ICONS.history}
          title={txs.length===0?"No transactions yet":"No matching transactions"}
          subtitle={txs.length===0?"Mine CYNC or use the faucet to receive your first transaction.":"Try adjusting your search or filters."}/>}
        {filtered.map(tx=>(
          <div key={tx.id} onClick={()=>setSelectedTx(tx)} style={{display:"grid",gridTemplateColumns:"2fr 150px 70px 75px",padding:"10px 16px",borderBottom:`1px solid ${T.b}`,alignItems:"center",cursor:"pointer",transition:"background .1s"}}
            onMouseEnter={e=>e.currentTarget.style.background=T.bg} onMouseLeave={e=>e.currentTarget.style.background=""}>
            <div style={{display:"flex",alignItems:"center",gap:8}}>
              <div style={{width:26,height:26,borderRadius:"50%",background:tx.type==="received"?`${T.green}18`:`${T.red}18`,display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0}}>
                <Ico d={tx.type==="received"?ICONS.receive:ICONS.send} size={11} color={tx.type==="received"?T.green:T.red}/>
              </div>
              <div><div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:10,color:T.t2}}>{tx.id}</div>{tx.memo&&<div style={{fontSize:9,color:T.t3}}>{tx.memo}</div>}</div>
            </div>
            <div style={{fontFamily:"'JetBrains Mono',monospace",fontSize:11,fontWeight:700,color:tx.type==="received"?T.green:T.red}}>{tx.type==="received"?"+":"-"}{tx.amount}</div>
            <div style={{fontSize:10,color:T.t3}}>{tx.date.split(" ")[0]}</div>
            <Badge label={tx.txType} color={tx.txType==="shielded"?T.blue:tx.txType==="coinbase"?T.amber:T.teal}/>
          </div>
        ))}
      </div>
      {selectedTx && <TxModal tx={selectedTx} onClose={()=>setSelectedTx(null)}/>}
    </div>
  );
}