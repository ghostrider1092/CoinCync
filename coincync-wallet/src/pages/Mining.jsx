import { useState, useEffect, useContext } from "react";
import { useTheme, Card, Badge, Btn, Lbl, Input, Ico, CoinLogo, ICONS } from "../components/ui";
import { WalletCtx, NotifCtx } from "../appContexts";
import { rpc } from "../utils/rpc";

export default function Mining() {
  const T = useTheme();
  const { push } = useContext(NotifCtx);
  const { mining } = useContext(WalletCtx);

  // Persist thread count in localStorage
  const [threads, setThreads] = useState(() => {
    const saved = localStorage.getItem("cc_mining_threads");
    return saved ? parseInt(saved) : 4;
  });
  const [miningAddr, setMiningAddr] = useState(() => localStorage.getItem("cc_mining_addr") || "");
  const [on, setOn] = useState(false);
  const [stats, setStats] = useState({ hashrate:0, shares:0, blocks:0 });
  const [error, setError] = useState("");

  // Auto-fill mining address from wallet if empty
  useEffect(() => {
    if (!miningAddr) {
      rpc.getWalletAddress().then(addr => {
        if (addr && addr.startsWith("tCYNC")) {
          setMiningAddr(addr);
          localStorage.setItem("cc_mining_addr", addr);
        }
      }).catch(() => {});
    }
  }, []);

  // Save thread count when changed
  function updateThreads(val) {
    setThreads(val);
    localStorage.setItem("cc_mining_threads", val.toString());
  }

  // Save address when changed
  function updateAddr(val) {
    setMiningAddr(val);
    localStorage.setItem("cc_mining_addr", val);
  }

  // Sync with shared mining state from Tauri backend
  useEffect(() => {
    if (mining && mining.is_mining) {
      setOn(true);
      setStats(s => ({
        hashrate: mining.hashrate || s.hashrate,
        shares: s.shares,
        blocks: mining.blocks_found || s.blocks,
      }));
    }
  }, [mining]);

  // Poll mining stats when running
  useEffect(() => {
    if (!on) return;
    const t = setInterval(async () => {
      try {
        const s = await rpc.getMiningStats();
        if (s) {
          setStats({ hashrate: s.hashrate || 0, shares: 0, blocks: s.blocks_found || 0 });
          if (!s.is_mining) { setOn(false); push("Miner stopped","info"); }
        }
      } catch {
        setOn(false);
        setError("Lost connection to miner backend");
        push("Miner backend unavailable", "error");
      }
    }, 3000);
    return () => clearInterval(t);
  }, [on, push]);

  async function toggle() {
    setError("");
    if (!miningAddr && !on) {
      push("Enter a tCYNC address first","warning");
      return;
    }

    if (!on) {
      try {
        const result = await rpc.startMining(miningAddr, threads);
        setOn(true);
        push(result || "Mining started","success");
      } catch (e) {
        const msg = String(e);
        if (msg.includes("not found") || msg.includes("program")) {
          setError("coincync-rig not installed. It should be in the same folder as the wallet app.");
        } else {
          setError(msg);
        }
        push("Failed: " + msg, "error");
      }
    } else {
      try { await rpc.stopMining(); } catch {}
      setOn(false);
      setStats({hashrate:0,shares:0,blocks:0});
      push("Mining stopped","info");
    }
  }

  const maxCores = navigator.hardwareConcurrency || 8;

  return (
    <div style={{animation:"fadeIn .2s ease",maxWidth:"100%"}}>
      <div style={{marginBottom:18}}>
        <h1 style={{fontFamily:T.serif,fontSize:21,fontWeight:400}}>Mining</h1>
        <p style={{fontSize:11,color:T.t3,marginTop:3}}>RandomX CPU-only · ASIC resistant · 2-min blocks</p>
      </div>
      <div style={{display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:10,marginBottom:14}}>
        {[
          ["Hashrate",on?Math.floor(stats.hashrate)+" H/s":"—",on?T.ac2:T.t3],
          ["Shares",on?stats.shares:"—",on?T.green:T.t3],
          ["Blocks",on?stats.blocks:"—",on?T.amber:T.t3],
          ["Threads",threads,T.blue],
        ].map(([l,v,c])=>(
          <Card key={l} style={{textAlign:"center",padding:"13px 15px"}}>
            <div style={{fontSize:9,fontWeight:700,color:T.t3,letterSpacing:.8,textTransform:"uppercase",marginBottom:3}}>{l}</div>
            <div style={{fontSize:18,fontWeight:700,fontFamily:T.mono,color:c}}>{v}</div>
          </Card>
        ))}
      </div>
      <Card>
        <div style={{display:"flex",flexDirection:"column",gap:12}}>
          <div style={{display:"flex",justifyContent:"center",marginBottom:4}}><CoinLogo size={52}/></div>
          <Input label="Mining Reward Address" value={miningAddr} onChange={e=>updateAddr(e.target.value)}
            placeholder="tCYNC3... your stealth address"
            hint="Block rewards (50 CYNC at genesis, decaying to 0.6 tail) are sent to this address."
            error={error}/>
          <div>
            <Lbl>CPU Threads: {threads} of {maxCores}</Lbl>
            <input type="range" min="1" max={maxCores} value={threads}
              onChange={e=>updateThreads(parseInt(e.target.value))}
              style={{width:"100%",accentColor:T.ac2,background:"none",border:"none",padding:"4px 0",cursor:"pointer"}}/>
            <div style={{display:"flex",justifyContent:"space-between",fontSize:9,color:T.t3}}>
              <span>1</span><span>{maxCores} cores</span>
            </div>
          </div>
          <div style={{background:T.bg,borderRadius:7,padding:"10px 12px",border:`1px solid ${T.b}`}}>
            <div style={{fontSize:12,fontWeight:600,marginBottom:3}}>RandomX · Asymptotic Emission</div>
            <div style={{fontSize:10,color:T.t3,marginBottom:6}}>
              2GB RAM per thread · 50 CYNC/block at genesis · 0.6 CYNC tail · 100M cap · 30% fee burn
            </div>
            {on && stats.hashrate > 0 && (
              <div style={{background:`${T.ac2}08`,borderRadius:6,padding:"8px 10px",border:`1px solid ${T.ac2}15`}}>
                <div style={{fontSize:10,fontWeight:600,color:T.ac2,marginBottom:2}}>Estimated Earnings</div>
                <div style={{display:"flex",gap:16,fontSize:10,color:T.t2}}>
                  <span>~{((stats.hashrate / 3600 * 50) * 3600).toFixed(1)} CYNC/hour</span>
                  <span>~{((stats.hashrate / 3600 * 50) * 86400).toFixed(0)} CYNC/day</span>
                </div>
                <div style={{fontSize:9,color:T.t3,marginTop:2}}>
                  Based on {Math.floor(stats.hashrate)} H/s at difficulty ~3,600
                </div>
              </div>
            )}
          </div>
          {on&&<div style={{display:"flex",alignItems:"center",gap:7,padding:"9px 11px",background:`${T.green}12`,borderRadius:7,border:`1px solid ${T.green}25`,fontSize:10,color:T.green}}>
            <div style={{width:7,height:7,borderRadius:"50%",background:T.green,animation:"pulse 1.2s infinite"}}/>
            Mining active · {threads} thread{threads>1?"s":""} · {Math.floor(stats.hashrate)} H/s
          </div>}
          <Btn onClick={toggle} variant={on?"danger":"primary"} full style={{padding:11,fontSize:13}}>
            <Ico d={on?"M18 6L6 18M6 6l12 12":ICONS.mining} size={14} color={on?T.red:"#fff"}/>
            {on?"Stop Mining":"Start Mining"}
          </Btn>
        </div>
      </Card>
    </div>
  );
}
