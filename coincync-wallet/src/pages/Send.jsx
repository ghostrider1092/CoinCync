import { useState, useEffect, useContext } from "react";
import { useTheme, Card, Badge, Btn, Lbl, Input, Ico, CoinLogo, ICONS } from "../components/ui";
import { rpc } from "../utils/rpc";
import { WalletCtx, NotifCtx } from "../App";

export default function Send() {
  const T = useTheme();
  const { balance, fees } = useContext(WalletCtx);
  const { push } = useContext(NotifCtx);
  const [addr, setAddr]         = useState("");
  const [amount, setAmount]     = useState("");
  const [memo, setMemo]         = useState("");
  const [priority, setPriority] = useState("normal");
  const [addrValid, setAddrValid] = useState(null);
  const [sending, setSending]   = useState(false);
  const [done, setDone]         = useState(false);
  const [txid, setTxid]         = useState("");

  useEffect(() => {
    if (!addr || addr.length < 5) { setAddrValid(null); return; }
    const t = setTimeout(async () => {
      try {
        const r = await rpc.validateAddress(addr);
        setAddrValid(r);
      } catch {
        setAddrValid({ valid: false, type: "unavailable" });
      }
    }, 400);
    return () => clearTimeout(t);
  }, [addr]);

  const [confirming, setConfirming] = useState(false);

  const feeMap = { slow:fees.slow, normal:fees.normal, fast:fees.fast, flash:fees.flash };
  const fee  = feeMap[priority] || "0.000005984000";
  const amountNum = parseFloat(amount) || 0;
  const feeNum = parseFloat(fee) || 0;
  const totalNum = amountNum + feeNum;
  const total = amount && amountNum > 0 ? totalNum.toFixed(6) : "—";
  const balanceNum = parseFloat(balance.unlocked) || 0;
  const amountError = amountNum > balanceNum ? "Exceeds balance" : amountNum < 0 ? "Must be positive" : "";

  function sendMax() {
    const max = Math.max(0, balanceNum - feeNum);
    setAmount(max > 0 ? max.toFixed(6) : "0");
  }

  function trySend() {
    if (!addr || !amount || !addrValid?.valid || amountNum <= 0 || amountError) return;
    setConfirming(true);
  }

  async function confirmSend() {
    setConfirming(false);
    setSending(true);
    try {
      const r = await rpc.sendTransaction({ to:addr, amount, memo, priority });
      setTxid(r.txid); setDone(true);
      push(`Sent! Tx: ${r.txid}`, "success");
    } catch(e) { push("Send failed: " + e, "error"); }
    setSending(false);
  }

  if (done) return (
    <div style={{ display:"flex", flexDirection:"column", alignItems:"center",
      justifyContent:"center", height:420, animation:"fadeIn .2s ease", gap:14 }}>
      <CoinLogo size={64}/>
      <div style={{ fontFamily:T.serif, fontSize:22, fontWeight:400 }}>Transaction Sent</div>
      <div style={{ fontFamily:T.mono, fontSize:11, color:T.t3 }}>Tx: {txid}</div>
      <div style={{ display:"flex", gap:7, flexWrap:"wrap", justifyContent:"center" }}>
        <Badge label="CLSAG ring-11" color={T.ac2}/>
        <Badge label="Pedersen committed" color={T.ac2}/>
        <Badge label="2-in 2-out shape" color={T.amber}/>
        <Badge label="Dandelion++ routed" color={T.blue}/>
        <Badge label="Traffic shaped" color={T.blue}/>
      </div>
      <Btn onClick={()=>{setDone(false);setAddr("");setAmount("");setMemo("");}}>Send Another</Btn>
    </div>
  );

  return (
    <div style={{ animation:"fadeIn .2s ease", maxWidth:"100%" }}>
      <div style={{ marginBottom:18 }}>
        <h1 style={{ fontFamily:T.serif, fontSize:21, fontWeight:400 }}>Send CYNC</h1>
        <p style={{ fontSize:11, color:T.t3, marginTop:3 }}>
          All transactions are constitutionally mandatory private — no opt-out
        </p>
      </div>

      <Card style={{ marginBottom:12, padding:"12px 16px" }}>
        <div style={{ fontSize:11, fontWeight:600, marginBottom:8, color:T.t1 }}>Every send applies automatically:</div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr 1fr", gap:6 }}>
          {[
            ["CLSAG Ring-11","11 decoys from entire UTXO set",T.ac2],
            ["Uniform Tx Shape","Always 2-in 2-out",T.amber],
            ["Pedersen Commits","Amounts cryptographically hidden",T.ac2],
            ["Bulletproofs+","Range proof on all outputs",T.ac2],
            ["Dandelion++","IP-hiding propagation",T.blue],
            ["Traffic Shaping","0-200ms jitter applied",T.amber],
          ].map(([t,d,c])=>(
            <div key={t} style={{ background:`${c}09`, border:`1px solid ${c}20`, borderRadius:7,
              padding:"7px 9px" }}>
              <div style={{ fontSize:10, fontWeight:600, color:c }}>{t}</div>
              <div style={{ fontSize:9, color:T.t3, marginTop:1 }}>{d}</div>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
          <Input label="Recipient Address" value={addr} onChange={e=>setAddr(e.target.value)}
            placeholder="tCYNC3... stealth address"
            right={addrValid===null?null:addrValid.valid
              ?<Ico d={ICONS.check} size={14} color={T.green}/>
              :<Ico d={ICONS.close} size={14} color={T.red}/>}
            error={addrValid&&!addrValid.valid?"Invalid address — must start with tCYNC or CYNC":""}
            hint={addrValid?.valid?`${addrValid.type} address · one-time stealth generated automatically`:""}/>

          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
            <Input label="Amount (CYNC)" value={amount}
              onChange={e=>setAmount(e.target.value.replace(/[^0-9.]/g,''))}
              placeholder="0.000000" mono
              error={amountError}
              right={<button onClick={sendMax} style={{background:"none",border:"none",color:T.ac2,fontSize:10,fontWeight:700,cursor:"pointer",padding:"2px 4px"}}>MAX</button>}/>
            <div>
              <Lbl>Available (unlocked)</Lbl>
              <div style={{ padding:"8px 12px", background:T.bg, border:`1px solid ${T.b}`, borderRadius:7,
                fontSize:12, fontFamily:T.mono, color:T.ac2 }}>
                {balance.unlocked||"—"} CYNC
              </div>
            </div>
          </div>

          <Input label="Encrypted Memo (ChaCha20+ECDH · 256 bytes)"
            value={memo} onChange={e=>setMemo(e.target.value)}
            placeholder="Optional — encrypted with recipient key, only they can read it"
            hint="ChaCha20Poly1305 encrypted, ECDH keyed. Only sender and receiver can read."/>

          <div>
            <Lbl>Fee Priority</Lbl>
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:6 }}>
              {[["slow","~10m"],["normal","~5m"],["fast","~2m"],["flash","~1m"]].map(([p,t])=>(
                <div key={p} onClick={()=>setPriority(p)} style={{ padding:"7px 6px", borderRadius:7,
                  textAlign:"center", cursor:"pointer",
                  border:`1px solid ${priority===p?T.ac2:T.b}`,
                  background:priority===p?T.acb:T.bg }}>
                  <div style={{ fontSize:11, fontWeight:600, color:priority===p?T.ac2:T.t2, textTransform:"capitalize" }}>{p}</div>
                  <div style={{ fontSize:9, color:T.t3 }}>{t}</div>
                  <div style={{ fontSize:8, fontFamily:T.mono, color:T.t3, marginTop:1 }}>{feeMap[p]||"…"} CYNC</div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ background:T.bg, borderRadius:7, padding:"10px 12px", border:`1px solid ${T.b}` }}>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:T.t3, marginBottom:5 }}>
              <span>Network fee ({priority})</span>
              <span style={{ fontFamily:T.mono }}>{fee} CYNC</span>
            </div>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:11, color:T.t3, marginBottom:5 }}>
              <span>Fee burn (30%)</span>
              <span style={{ fontFamily:T.mono, color:T.amber }}>{(parseFloat(fee)*0.3).toFixed(12)} CYNC</span>
            </div>
            <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, fontWeight:700 }}>
              <span>Total</span>
              <span style={{ fontFamily:T.mono }}>{total} CYNC</span>
            </div>
          </div>

          <Btn onClick={trySend} disabled={!addr||!amount||amountNum<=0||!addrValid?.valid||sending||!!amountError} full style={{ padding:11, fontSize:13 }}>
            {sending
              ? <div style={{ width:16, height:16, border:"2px solid #fff", borderTopColor:"transparent", borderRadius:"50%", animation:"spin .7s linear infinite" }}/>
              : <Ico d={ICONS.send} size={14} color="#fff"/>}
            {sending ? "Sending…" : "Send CYNC"}
          </Btn>

          {/* Confirmation Dialog */}
          {confirming && (
            <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.7)", display:"flex",
              alignItems:"center", justifyContent:"center", zIndex:9999, animation:"fadeInFast .15s" }}>
              <Card style={{ maxWidth:420, width:"90%", padding:"24px" }}>
                <div style={{ textAlign:"center", marginBottom:16 }}>
                  <div style={{ fontSize:18, fontWeight:600, marginBottom:4 }}>Confirm Transaction</div>
                  <div style={{ fontSize:11, color:T.t3 }}>This action cannot be undone</div>
                </div>
                <div style={{ background:T.bg, borderRadius:8, padding:"12px 14px", marginBottom:12 }}>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, marginBottom:6 }}>
                    <span style={{ color:T.t3 }}>To</span>
                    <span style={{ fontFamily:T.mono, fontSize:10, color:T.t2 }}>{addr.slice(0,20)}...{addr.slice(-8)}</span>
                  </div>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, marginBottom:6 }}>
                    <span style={{ color:T.t3 }}>Amount</span>
                    <span style={{ fontFamily:T.mono, fontWeight:600, color:T.ac2 }}>{amountNum.toFixed(6)} CYNC</span>
                  </div>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, marginBottom:6 }}>
                    <span style={{ color:T.t3 }}>Fee</span>
                    <span style={{ fontFamily:T.mono, fontSize:11, color:T.t2 }}>{fee} CYNC</span>
                  </div>
                  <div style={{ display:"flex", justifyContent:"space-between", fontSize:12, fontWeight:700, borderTop:`1px solid ${T.b}`, paddingTop:6 }}>
                    <span>Total</span>
                    <span style={{ fontFamily:T.mono }}>{total} CYNC</span>
                  </div>
                </div>
                <div style={{ display:"flex", gap:8 }}>
                  <Btn variant="ghost" full onClick={()=>setConfirming(false)}>Cancel</Btn>
                  <Btn full onClick={confirmSend}>Confirm Send</Btn>
                </div>
              </Card>
            </div>
          )}
        </div>
      </Card>
    </div>
  );
}
