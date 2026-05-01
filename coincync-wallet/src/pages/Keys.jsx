import { useState, useContext } from "react";
import { useTheme, Card, Badge, Btn, Lbl, Input, Ico, Divider, ICONS } from "../components/ui";
import { NotifCtx } from "../appContexts";

export default function Keys() {
  const T = useTheme();
  const { push } = useContext(NotifCtx);
  const [show, setShow] = useState({});
  const [frostK, setFrostK] = useState(2);
  const [frostN, setFrostN] = useState(3);
  const [scopeFrom, setScopeFrom] = useState("");
  const [scopeTo, setScopeTo] = useState("");
  const [decoyPw, setDecoyPw] = useState("");
  const [realPw, setRealPw] = useState("");

  const keys = [
    { id:"ivk", l:"Incoming Viewing Key (IVK)", p:"yivk",
      d:"Decrypts received outputs only. Share with exchange for deposit detection, auditor for one-way verification.", c:T.teal, r:"Safe" },
    { id:"fvk", l:"Full Viewing Key (FVK)", p:"yfvk",
      d:"Decrypts all inputs and outputs. Use for court orders, full audit packages. Never share with untrusted parties.", c:T.amber, r:"Sensitive" },
    { id:"ovk", l:"Outgoing Viewing Key (OVK)", p:"yovk",
      d:"Decrypts your own sends. Required for sender-side tax reporting.", c:T.blue, r:"Private" },
  ];

  return (
    <div style={{ animation:"fadeIn .2s ease", maxWidth:"100%" }}>
      <div style={{ marginBottom:18 }}>
        <h1 style={{ fontSize:21, fontWeight:700 }}>Keys & Multi-Sig</h1>
        <p style={{ fontSize:11, color:T.t3, marginTop:3 }}>
          Selective disclosure · Time-scoped views · FROST threshold signatures
        </p>
        <p style={{ fontSize:10, color:T.t3, marginTop:6 }}>
          This page combines enforced key primitives with advanced wallet workflows; workflow availability can depend on backend/runtime configuration.
        </p>
      </div>

      {/* Viewing keys */}
      <div style={{ display:"flex", flexDirection:"column", gap:10, marginBottom:12 }}>
        {keys.map(k => (
          <Card key={k.id}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"flex-start", marginBottom:9 }}>
              <div>
                <div style={{ fontSize:12, fontWeight:600, color:k.c, marginBottom:2 }}>{k.l}</div>
                <div style={{ fontSize:10, color:T.t3, maxWidth:420 }}>{k.d}</div>
              </div>
              <Badge label={k.r} color={k.r==="Sensitive"?T.red:k.r==="Private"?T.amber:T.green}/>
            </div>
            <div style={{ background:T.bg, border:`1px solid ${T.b}`, borderRadius:7,
              padding:"8px 11px", marginBottom:8, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
              <span style={{ fontFamily:"'JetBrains Mono',monospace", fontSize:10, color:k.c }}>
                {show[k.id] ? `${k.p}1aBcDeFgHiJkLmNoPqRsTuVwXyZ01234...` : `${k.p}1${"•".repeat(32)}`}
              </span>
              <div style={{ display:"flex", gap:4 }}>
                <button onClick={()=>setShow(s=>({...s,[k.id]:!s[k.id]}))}
                  style={{ background:"none", border:"none", cursor:"pointer", color:T.t3, padding:"2px 4px" }}>
                  <Ico d={show[k.id]?ICONS.eyeOff:ICONS.eye} size={13}/>
                </button>
                <button onClick={()=>{ navigator.clipboard?.writeText(`${k.p}1aBcDe...`); push("Key copied","success"); }}
                  style={{ background:"none", border:"none", cursor:"pointer", color:T.t3, padding:"2px 4px" }}>
                  <Ico d={ICONS.copy} size={13}/>
                </button>
              </div>
            </div>
            <div style={{ display:"flex", gap:7 }}>
              <Btn small>Export JSON</Btn>
              <Btn small variant="ghost">QR Code</Btn>
            </div>
          </Card>
        ))}
      </div>

      {/* Time-Scoped View Keys */}
      <Card style={{ marginBottom:12 }}>
        <div style={{ fontSize:13, fontWeight:600, marginBottom:4, display:"flex", alignItems:"center", gap:8 }}>
          Time-Scoped View Keys
          <Badge label="L3 Wallet" color={T.amber}/>
        </div>
        <div style={{ fontSize:10, color:T.t3, marginBottom:14 }}>
          Export a view key that only decrypts outputs between two block heights.
          Auditors see exactly what you allow — nothing before or after the range.
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:12 }}>
          <Input label="From Block Height" value={scopeFrom} onChange={e=>setScopeFrom(e.target.value)} placeholder="e.g. 100000" mono/>
          <Input label="To Block Height"   value={scopeTo}   onChange={e=>setScopeTo(e.target.value)}   placeholder="e.g. 142857" mono/>
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginBottom:12 }}>
          {[["Audit (FVK scoped)","Full in/out, block range only",T.amber],
            ["Income (IVK scoped)","Received only, block range",T.teal]].map(([l,d,c])=>(
            <div key={l} style={{ padding:"10px 12px", background:`${c}09`, borderRadius:8, border:`1px solid ${c}20` }}>
              <div style={{ fontSize:11, fontWeight:600, color:c, marginBottom:2 }}>{l}</div>
              <div style={{ fontSize:9, color:T.t3 }}>{d}</div>
            </div>
          ))}
        </div>
        <Btn small onClick={()=>push("Time-scoped view key generated","success")}>
          Generate Scoped Key
        </Btn>
      </Card>

      {/* FROST Multi-Sig */}
      <Card style={{ marginBottom:12 }}>
        <div style={{ fontSize:13, fontWeight:600, marginBottom:4, display:"flex", alignItems:"center", gap:8 }}>
          FROST Threshold Multi-Sig
          <Badge label="L3 Wallet" color={T.blue}/>
        </div>
        <div style={{ fontSize:10, color:T.t3, marginBottom:14 }}>
          FROST produces signatures indistinguishable from single-sig on-chain.
          Nobody can tell a 2-of-3 multi-sig from a normal transaction.
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:12 }}>
          <div>
            <Lbl>Threshold (K — required signers)</Lbl>
            <div style={{ display:"flex", alignItems:"center", gap:8 }}>
              <button onClick={()=>setFrostK(k=>Math.max(1,k-1))} style={{ background:T.b, border:"none", color:T.t1, borderRadius:6, padding:"4px 10px", cursor:"pointer", fontSize:14 }}>−</button>
              <div style={{ flex:1, textAlign:"center", fontFamily:"'JetBrains Mono',monospace", fontSize:18, fontWeight:700, color:T.blue }}>{frostK}</div>
              <button onClick={()=>setFrostK(k=>Math.min(frostN,k+1))} style={{ background:T.b, border:"none", color:T.t1, borderRadius:6, padding:"4px 10px", cursor:"pointer", fontSize:14 }}>+</button>
            </div>
          </div>
          <div>
            <Lbl>Total Participants (N)</Lbl>
            <div style={{ display:"flex", alignItems:"center", gap:8 }}>
              <button onClick={()=>setFrostN(n=>Math.max(frostK,n-1))} style={{ background:T.b, border:"none", color:T.t1, borderRadius:6, padding:"4px 10px", cursor:"pointer", fontSize:14 }}>−</button>
              <div style={{ flex:1, textAlign:"center", fontFamily:"'JetBrains Mono',monospace", fontSize:18, fontWeight:700, color:T.blue }}>{frostN}</div>
              <button onClick={()=>setFrostN(n=>n+1)} style={{ background:T.b, border:"none", color:T.t1, borderRadius:6, padding:"4px 10px", cursor:"pointer", fontSize:14 }}>+</button>
            </div>
          </div>
        </div>
        <div style={{ padding:"10px 12px", background:`${T.blue}09`, borderRadius:8, border:`1px solid ${T.blue}20`, marginBottom:12, fontSize:10, color:T.blue }}>
          {frostK}-of-{frostN} threshold · On-chain indistinguishable from single-sig · No coordinator required
        </div>
        <div style={{ display:"flex", gap:8 }}>
          <Btn small onClick={()=>push(`FROST ${frostK}-of-${frostN} wallet initialized`,"success")}>
            Initialize FROST Wallet
          </Btn>
          <Btn small variant="ghost">Add Participant</Btn>
        </div>
      </Card>

      {/* Plausible Deniability */}
      <Card style={{ marginBottom:12 }}>
        <div style={{ fontSize:13, fontWeight:600, marginBottom:4, display:"flex", alignItems:"center", gap:8 }}>
          Plausible Deniability Wallet
          <Badge label="L3 Wallet" color={T.amber}/>
        </div>
        <div style={{ fontSize:10, color:T.t3, marginBottom:14 }}>
          Dual-password encryption. One password opens a decoy wallet with small funds.
          The other opens the real wallet. Same encrypted file — cryptographically indistinguishable.
        </div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10, marginBottom:12 }}>
          <Input label="Decoy Wallet Password" value={decoyPw} onChange={e=>setDecoyPw(e.target.value)}
            type="password" placeholder="Opens decoy wallet" hint="Keep small amount here"/>
          <Input label="Real Wallet Password" value={realPw} onChange={e=>setRealPw(e.target.value)}
            type="password" placeholder="Opens real wallet" hint="Your actual funds"/>
        </div>
        <Btn small onClick={()=>push("Plausible deniability wallet configured","success")}
          disabled={!decoyPw||!realPw||decoyPw===realPw}>
          Configure Deniability
        </Btn>
      </Card>

      {/* Selective disclosure proofs */}
      <Card>
        <div style={{ fontSize:13, fontWeight:600, marginBottom:3 }}>Selective Disclosure Proofs</div>
        <div style={{ fontSize:10, color:T.t3, marginBottom:12 }}>
          Zero-knowledge proofs — reveal exactly what you choose, nothing more.
        </div>
        {[
          ["Balance Proof",   "Prove balance ≥ threshold · no value revealed · exchange KYC"],
          ["Ownership Proof", "Prove output ownership · bound to challenge string · court order"],
          ["Sum Proof",       "Prove period total received · IRS Form 8949 / tax reporting"],
          ["Source Proof",    "Key image provenance · AML source-of-funds verification"],
        ].map(([l,d]) => (
          <div key={l} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
            padding:"8px 0", borderBottom:`1px solid ${T.b}` }}>
            <div>
              <div style={{ fontSize:11, fontWeight:500 }}>{l}</div>
              <div style={{ fontSize:9, color:T.t3 }}>{d}</div>
            </div>
            <Btn small onClick={()=>push(`${l} generated`,"success")}>Generate</Btn>
          </div>
        ))}
      </Card>
    </div>
  );
}
