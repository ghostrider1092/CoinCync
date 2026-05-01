import { useContext, useState } from "react";
import { useTheme, Card, Badge, Ico, CoinLogo, ICONS, StatCard } from "../components/ui";
import Globe3D from "../components/Globe3D";
import BalanceChart from "../components/BalanceChart";
import { WalletCtx } from "../appContexts";
import { rpc } from "../utils/rpc";

const ALL_LAYERS = [
  // Layer 1: Cryptographic (7)
  { n:"CLSAG Ring-11",        layer:1, on:true },
  { n:"Stealth Addresses",    layer:1, on:true },
  { n:"Pedersen Commitments",  layer:1, on:true },
  { n:"Bulletproofs+",        layer:1, on:true },
  { n:"Encrypted Memos",      layer:1, on:true },
  { n:"Key Images",           layer:1, on:true },
  { n:"View Tags",            layer:1, on:true },
  // Layer 2: Network (4)
  { n:"Dandelion++",          layer:2, on:true },
  { n:"Noise_XX P2P",         layer:2, on:true },
  { n:"Traffic Shaping",      layer:2, on:true },
  { n:"Constant-Rate Padding",layer:2, on:true },
  // Layer 3: Wallet (7)
  { n:"Uniform Decoys",       layer:3, on:true },
  { n:"Time-Scoped View Keys",layer:3, on:true },
  { n:"Plausible Deniability", layer:3, on:true },
  { n:"Auto-Churn",           layer:3, on:true },
  { n:"Dead Man's Switch",    layer:3, on:true },
  { n:"Uniform Tx Shape",     layer:3, on:true },
  { n:"FROST Multi-Sig",      layer:3, on:true },
  // Layer 4: Constitutional (4)
  { n:"Mandatory Privacy",    layer:4, on:true },
  { n:"No Surveillance",      layer:4, on:true },
  { n:"No Balance Lookup",    layer:4, on:true },
  { n:"4th Amendment",        layer:4, on:true },
];


export default function Dashboard() {
  const T = useTheme();
  const { balance, syncInfo, rsaState, txs, loading, mining, scanning, scanResult, scanWallet } = useContext(WalletCtx);
  const synced = syncInfo.syncPct >= 99.9;

  const layerColors = { 1:T.ac2, 2:T.blue, 3:T.amber, 4:"#EF4444" };
  const layerLabels = { 1:"L1 Cryptographic", 2:"L2 Network", 3:"L3 Wallet", 4:"L4 Constitutional" };

  return (
    <div style={{ animation:"fadeIn .3s ease" }}>
      {/* Hero */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:24 }}>
        <div>
          <h1 style={{ fontFamily:T.serif, fontSize:28, fontWeight:400, marginBottom:4 }}>Dashboard</h1>
          <p style={{ fontFamily:T.serif, fontStyle:"italic", fontSize:13, color:T.ac2 }}>
            Private by law. Private by math.
          </p>
        </div>
        <div style={{ display:"flex", gap:8, alignItems:"center" }}>
          {mining.is_mining && <Badge label={`Mining ${mining.hashrate?.toFixed(0)||0} H/s`} color={T.amber}/>}
          <Badge label="22 privacy features" color={T.ac2}/>
          <button onClick={scanWallet} disabled={scanning}
            style={{ background:T.acb, border:`1px solid ${T.ac2}30`, borderRadius:8,
              padding:"4px 12px", fontSize:10, fontWeight:600, color:T.ac2,
              cursor:scanning?"wait":"pointer", display:"flex", alignItems:"center", gap:4 }}>
            <Ico d={ICONS.refresh} size={11} color={T.ac2}/>
            {scanning?"Scanning...":"Scan Wallet"}
          </button>
          {scanResult && <span style={{fontSize:9,color:T.t3,maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap"}}>{scanResult}</span>}
        </div>
      </div>

      {/* Balance Hero */}
      <Card style={{ marginBottom:20, padding:"20px 24px",
        background:`linear-gradient(135deg, ${T.card}, ${T.ac2}08)`,
        border:`1px solid ${T.ac2}20` }}>
        <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div>
            <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.8, textTransform:"uppercase", marginBottom:6 }}>Total Balance</div>
            <div style={{ fontFamily:T.mono, fontSize:32, fontWeight:700, color:T.ac2, letterSpacing:-.5 }}>
              {balance.total && balance.total !== "—"
                ? <>{balance.total.split(".")[0]}<span style={{ fontSize:18, fontWeight:400, color:T.t2 }}>.{(balance.total.split(".")[1]||"0000").slice(0,4)}</span><span style={{ fontSize:14, fontWeight:400, color:T.t3, marginLeft:6 }}>CYNC</span></>
                : <span style={{ color:T.t3 }}>0.0000 <span style={{ fontSize:14 }}>CYNC</span></span>
              }
            </div>
          </div>
          <div style={{ textAlign:"right" }}>
            <div style={{ fontSize:10, color:T.t3, marginBottom:4 }}>
              {txs.length} transaction{txs.length!==1?"s":""}
            </div>
            <div style={{ fontSize:10, color:synced?T.ac2:T.amber, fontFamily:T.mono }}>
              {synced?"Synced":"Syncing..."} · Block {syncInfo.height?.toLocaleString()||"—"}
            </div>
          </div>
        </div>
      </Card>

      {/* Portfolio Chart + Recent Activity */}
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:16, marginBottom:20 }}>
        <Card style={{ padding:"14px 16px" }}>
          <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.6, textTransform:"uppercase", marginBottom:8 }}>Balance History</div>
          <BalanceChart width={380} height={100} data={
            txs.length > 0
              ? txs.slice().reverse().map((tx, i) => ({
                  value: parseFloat(tx.amount) * (i+1),
                  label: i===0 ? "First" : i===txs.length-1 ? "Now" : ""
                }))
              : [{value:0,label:"Start"},{value:0,label:"Now"}]
          }/>
        </Card>
        <Card style={{ padding:"14px 16px" }}>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:8 }}>
            <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.6, textTransform:"uppercase" }}>Recent Activity</div>
            <button onClick={()=>{}} style={{ background:"none", border:"none", color:T.ac2, fontSize:10, cursor:"pointer" }}>View all</button>
          </div>
          {txs.length === 0
            ? <div style={{ fontSize:11, color:T.t3, textAlign:"center", padding:"20px 0" }}>No transactions yet. Mine or use the faucet to get CYNC.</div>
            : txs.slice(0,4).map(tx => (
                <div key={tx.id} style={{ display:"flex", justifyContent:"space-between", alignItems:"center",
                  padding:"6px 0", borderBottom:`1px solid ${T.b}` }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <div style={{ width:24, height:24, borderRadius:6,
                      background: tx.type==="received" ? `${T.ac2}15` : `${T.red}15`,
                      display:"flex", alignItems:"center", justifyContent:"center" }}>
                      <Ico d={tx.type==="received"?ICONS.arrowDown:ICONS.arrowUp} size={12}
                        color={tx.type==="received"?T.ac2:T.red}/>
                    </div>
                    <div>
                      <div style={{ fontSize:11, fontWeight:500 }}>{tx.type==="received"?"Received":"Sent"}</div>
                      <div style={{ fontSize:9, color:T.t3 }}>Block {tx.height}</div>
                    </div>
                  </div>
                  <div style={{ fontFamily:T.mono, fontSize:11, fontWeight:600,
                    color: tx.type==="received"?T.ac2:T.red }}>
                    {tx.type==="received"?"+":"−"}{parseFloat(tx.amount).toFixed(2)} CYNC
                  </div>
                </div>
              ))
          }
          {/* Faucet button */}
          <button onClick={async () => {
            try {
              const walletAddr = await rpc.getWalletAddress();
              if (!walletAddr) { alert("Could not get wallet address. Open the Receive page first."); return; }
              const resp = await fetch("https://explorer.coincync.network/faucet/", {
                method:"POST", headers:{"Content-Type":"application/json"},
                body: JSON.stringify({ address: walletAddr })
              });
              const d = await resp.json();
              if (d.success) alert("Faucet sent 10 CYNC! Scan wallet to see it.");
              else alert(d.error || "Faucet request failed");
            } catch { alert("Faucet unavailable — use the explorer faucet at explorer.coincync.network"); }
          }} style={{ marginTop:8, width:"100%", padding:"6px", borderRadius:8, border:`1px dashed ${T.ac2}40`,
            background:"transparent", color:T.ac2, fontSize:10, fontWeight:600, cursor:"pointer" }}>
            Get free testnet CYNC (faucet)
          </button>
        </Card>
      </div>

      {/* Globe + Stats */}
      <div style={{ display:"grid", gridTemplateColumns:"220px 1fr", gap:20, marginBottom:24 }}>
        <Card style={{ display:"flex", alignItems:"center", justifyContent:"center", padding:0, overflow:"hidden" }}>
          <Globe3D width={220} height={220}/>
        </Card>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:12 }}>
          <Card>
            <div style={{ fontSize:9, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:8 }}>Block Height</div>
            <div style={{ fontFamily:T.serif, fontSize:28, color:T.ac2 }}>{syncInfo.height?.toLocaleString()||"—"}</div>
            <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>{syncInfo.syncPct?.toFixed(1)||0}% synced</div>
          </Card>
          <Card>
            <div style={{ fontSize:9, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:8 }}>Supply Cap</div>
            <div style={{ fontFamily:T.serif, fontSize:28, color:T.t1 }}>100M</div>
            <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>CYNC · asymptotic curve</div>
          </Card>
          <Card>
            <div style={{ fontSize:9, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:8 }}>Ring Size</div>
            <div style={{ fontFamily:T.serif, fontSize:28, color:T.t1 }}>11</div>
            <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>CLSAG decoys</div>
          </Card>
          <Card>
            <div style={{ fontSize:9, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:8 }}>Fee Burn</div>
            <div style={{ fontFamily:T.serif, fontSize:28, color:T.amber }}>30%</div>
            <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>permanently destroyed</div>
          </Card>
          <Card>
            <div style={{ fontSize:9, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:8 }}>Tail Emission</div>
            <div style={{ fontFamily:T.serif, fontSize:28, color:T.t1 }}>0.6</div>
            <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>CYNC/block forever</div>
          </Card>
          <Card>
            <div style={{ fontSize:9, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:8 }}>Dev Tax</div>
            <div style={{ fontFamily:T.serif, fontSize:28, color:T.ac2 }}>0%</div>
            <div style={{ fontSize:10, color:T.t3, marginTop:4 }}>Constitution Article II</div>
          </Card>
        </div>
      </div>

      {/* Privacy Features Matrix */}
      <Card style={{ marginBottom:24 }}>
        <div style={{ fontSize:11, fontWeight:700, color:T.t3, letterSpacing:1, textTransform:"uppercase", marginBottom:14 }}>Privacy Layers — 22 Features Active</div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:12 }}>
          {[1,2,3,4].map(layer => (
            <div key={layer}>
              <div style={{ fontSize:10, fontWeight:700, color:layerColors[layer], marginBottom:8, fontFamily:T.mono }}>
                {layerLabels[layer]}
              </div>
              {ALL_LAYERS.filter(f=>f.layer===layer).map(f => (
                <div key={f.n} style={{ display:"flex", alignItems:"center", gap:6, marginBottom:4 }}>
                  <div style={{ width:6, height:6, borderRadius:"50%", background:f.on?layerColors[layer]:T.t3 }}/>
                  <span style={{ fontSize:10, color:f.on?T.t1:T.t3 }}>{f.n}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </Card>

      {/* 4th Amendment */}
      <div style={{ textAlign:"center", padding:"16px 0", borderTop:`1px solid ${T.b}` }}>
        <div style={{ fontFamily:T.serif, fontStyle:"italic", fontSize:12, color:T.t3, lineHeight:1.6, maxWidth:500, margin:"0 auto" }}>
          "The right of the people to be secure in their persons, houses, papers, and effects, against unreasonable searches and seizures, shall not be violated."
        </div>
        <div style={{ fontFamily:T.mono, fontSize:9, color:T.t3, marginTop:6, letterSpacing:1 }}>
          FOURTH AMENDMENT · U.S. CONSTITUTION · 1791
        </div>
      </div>
    </div>
  );
}
