import React, { useState, useEffect } from "react";
import { useTheme, Card, Badge, Btn, Lbl, Mono, Divider, Ico, ICONS } from "../components/ui";
import QRCode from "../components/QRCode";
import { rpc } from "../utils/rpc";

export default function Receive() {
  const T = useTheme();
  const [addr, setAddr] = useState("");
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const a = await rpc.getWalletAddress();
        if (a) setAddr(a);
      } catch {}
      setLoading(false);
    })();
  }, []);

  function copyAddr(text) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true); setTimeout(()=>setCopied(false), 1500);
      });
    } else {
      const ta = document.createElement("textarea");
      ta.value = text; document.body.appendChild(ta);
      ta.select(); document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true); setTimeout(()=>setCopied(false), 1500);
    }
  }

  async function generateNew() {
    setLoading(true);
    try {
      const a = await rpc.getWalletAddress();
      if (a) setAddr(a);
    } catch {}
    setLoading(false);
  }

  return (
    <div style={{animation:"fadeIn .2s ease",maxWidth:"100%"}}>
      <div style={{marginBottom:18}}>
        <h1 style={{fontFamily:T.serif,fontSize:21,fontWeight:400}}>Receive CYNC</h1>
        <p style={{fontSize:11,color:T.t3,marginTop:3}}>One-time stealth addresses — public key never appears on-chain</p>
      </div>
      <Card>
        {loading ? (
          <div style={{textAlign:"center",padding:"40px 0",color:T.t3,fontSize:12}}>
            <div style={{width:20,height:20,border:`2px solid ${T.ac2}`,borderTopColor:"transparent",borderRadius:"50%",animation:"spin .7s linear infinite",margin:"0 auto 10px"}}/>
            Loading wallet address...
          </div>
        ) : (
          <>
            <div style={{display:"flex",gap:18,alignItems:"flex-start"}}>
              <div style={{flexShrink:0,border:`1px solid ${T.b}`,borderRadius:10,padding:6,background:T.bg}}>
                <QRCode value={addr} size={140}/>
              </div>
              <div style={{flex:1}}>
                <Lbl>Stealth Address (tCYNC...)</Lbl>
                <div style={{background:T.bg,border:`1px solid ${T.b}`,borderRadius:7,padding:"9px 11px",marginBottom:9,cursor:"pointer",userSelect:"all",wordBreak:"break-all"}}
                  onClick={()=>copyAddr(addr)}>
                  <Mono size={10} color={T.ac2}>{addr}</Mono>
                </div>
                <div style={{display:"flex",gap:7,marginBottom:9}}>
                  <Btn small onClick={()=>copyAddr(addr)}>
                    <Ico d={copied?ICONS.check:ICONS.copy} size={12} color="#000"/>
                    {copied?"Copied!":"Copy Address"}
                  </Btn>
                  <Btn small variant="ghost" onClick={generateNew}>New Address</Btn>
                </div>
                <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
                  <Badge label="Stealth · 1-time" color={T.ac2}/>
                  <Badge label="Ristretto255" color={T.ac2}/>
                  <Badge label="View tag 1-byte" color={T.green}/>
                </div>
              </div>
            </div>

            <Divider/>

            <div style={{padding:"12px 0"}}>
              <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                <Ico d={ICONS.lock} size={14} color={T.ac2}/>
                <div style={{fontSize:12,fontWeight:600}}>How Stealth Addresses Work</div>
              </div>
              <div style={{fontSize:11,color:T.t3,lineHeight:1.6}}>
                Each sender derives a unique one-time address from your public key. The actual destination
                never appears on-chain — only the sender and you can link the payment. This means your
                address can be shared publicly without compromising privacy.
              </div>
            </div>
          </>
        )}
      </Card>
    </div>
  );
}
