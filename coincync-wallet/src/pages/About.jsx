import { useTheme, Card, Ico, CoinLogo, ICONS, Divider } from "../components/ui";

export default function About() {
  const T = useTheme();
  const link = (url, text) => (
    <a href={url} target="_blank" rel="noopener noreferrer"
      style={{ color:T.ac2, textDecoration:"none", fontSize:11 }}
      onClick={(e) => { e.preventDefault(); window.__TAURI__?.shell?.open(url) || window.open(url); }}>
      {text} ↗
    </a>
  );

  return (
    <div style={{ animation:"fadeIn .2s ease", maxWidth:"100%" }}>
      <div style={{ textAlign:"center", marginBottom:24 }}>
        <CoinLogo size={64}/>
        <h1 style={{ fontFamily:T.serif, fontSize:24, fontWeight:400, marginTop:16 }}>CoinCync Wallet</h1>
        <div style={{ fontFamily:T.serif, fontStyle:"italic", fontSize:13, color:T.ac2, marginTop:4 }}>
          Private by law. Private by math.
        </div>
        <div style={{ fontFamily:T.mono, fontSize:10, color:T.t3, marginTop:8 }}>v1.0.0 · Testnet</div>
      </div>

      <Card style={{ marginBottom:14 }}>
        <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.8, textTransform:"uppercase", marginBottom:10 }}>Links</div>
        <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
          {link("https://explorer.coincync.network", "Block Explorer")}
          {link("https://github.com/CyncDevelopment/Cync-Protocol", "GitHub Repository")}
          {link("https://explorer.coincync.network/#page-4thamendment", "The 4th Amendment")}
          {link("https://explorer.coincync.network/#page-constitution", "Constitution")}
        </div>
      </Card>

      <Card style={{ marginBottom:14 }}>
        <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.8, textTransform:"uppercase", marginBottom:10 }}>Specifications</div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6, fontSize:11 }}>
          {[
            ["Ticker","CYNC"],["Supply Cap","100,000,000"],["Decimals","12"],
            ["Algorithm","RandomX (CPU)"],["Block Time","120 seconds"],["Ring Size","11"],
            ["Range Proofs","Bulletproofs+"],["Addresses","Ristretto255 Stealth"],
            ["Fee Burn","30% / 50%"],["Tail Emission","0.6 CYNC/block"],
            ["Dev Tax","0%"],["Privacy","Mandatory"],
          ].map(([k,v]) => (
            <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"4px 0",
              borderBottom:`1px solid ${T.b}` }}>
              <span style={{ color:T.t3 }}>{k}</span>
              <span style={{ color:T.t1, fontFamily:T.mono, fontSize:10 }}>{v}</span>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.8, textTransform:"uppercase", marginBottom:10 }}>Keyboard Shortcuts</div>
        <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:4, fontSize:11 }}>
          {[
            ["Ctrl+D","Dashboard"],["Ctrl+S","Send"],["Ctrl+R","Receive"],
            ["Ctrl+M","Mining"],["Ctrl+H","History"],["Ctrl+L","Lock Wallet"],
          ].map(([k,v]) => (
            <div key={k} style={{ display:"flex", justifyContent:"space-between", padding:"3px 0" }}>
              <span style={{ color:T.t3 }}>{v}</span>
              <kbd style={{ background:T.b, borderRadius:4, padding:"1px 6px", fontSize:9,
                fontFamily:T.mono, color:T.t2 }}>{k}</kbd>
            </div>
          ))}
        </div>
      </Card>

      <div style={{ textAlign:"center", padding:"20px 0", fontFamily:T.serif, fontStyle:"italic",
        fontSize:11, color:T.t3 }}>
        22 privacy features · 0% dev tax · 100M CYNC cap · CPU-only RandomX
      </div>
    </div>
  );
}
