import { useState } from "react";
import { useTheme, CoinLogo, Btn, Input, Ico, ICONS } from "../components/ui";
import { rpc } from "../utils/rpc";

export default function Unlock({ onUnlock }) {
  const T = useTheme();
  const [pw, setPw]   = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  async function tryUnlock() {
    if (!pw) { setErr("Enter your password"); return; }
    setLoading(true);
    setErr("");
    try {
      const result = await rpc.unlockWallet(pw);
      if (result) { onUnlock(); }
      else { setErr("Incorrect password"); }
    } catch (e) {
      setErr(String(e || "Unlock failed"));
    }
    setLoading(false);
  }

  return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg }}>
      <div style={{ background:T.card, border:`1px solid ${T.b}`, borderRadius:14, padding:"36px 40px",
        width:380, textAlign:"center", boxShadow:`0 20px 60px ${T.shadow}` }}>
        <div style={{ marginBottom:20 }}><CoinLogo size={64}/></div>
        <h2 style={{ fontSize:20, fontWeight:700, marginBottom:4 }}>CoinCync Wallet</h2>
        <p style={{ fontSize:12, color:T.t2, marginBottom:24 }}>Enter your password to unlock</p>
        <div style={{ textAlign:"left", marginBottom:16 }}>
          <Input value={pw} onChange={e=>{setPw(e.target.value);setErr("");}}
            type="password" placeholder="Wallet password..." error={err}
            right={loading?<div style={{ width:14, height:14, border:`2px solid ${T.teal}`, borderTopColor:"transparent", borderRadius:"50%", animation:"spin .7s linear infinite" }}/>:null}/>
        </div>
        <Btn onClick={tryUnlock} disabled={!pw||loading} full>
          <Ico d={ICONS.unlock} size={14} color="#000"/> Unlock
        </Btn>
        <div style={{ fontSize:11, color:T.t3, marginTop:16, cursor:"pointer" }}
          onClick={()=>{ if(confirm("This will delete your wallet. Make sure you have your seed phrase!")) { localStorage.clear(); window.location.reload(); } }}>
          Forgot password? (requires seed)
        </div>
      </div>
    </div>
  );
}
