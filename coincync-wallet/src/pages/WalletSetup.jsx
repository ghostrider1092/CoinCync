import { useState } from "react";
import { useTheme, CoinLogo, Btn, Input, Ico, ICONS } from "../components/ui";
import { markWalletCreated, markSeedBackedUp } from "../utils/storage";
import { rpc } from "../utils/rpc";

export default function WalletSetup({ onComplete }) {
  const T = useTheme();
  const [step, setStep]       = useState("choose"); // choose | create | restore | backup
  const [seed, setSeed]       = useState("");
  const [confirmWords, setConfirmWords] = useState({});
  const [checkIdxs, setCheckIdxs] = useState([]);
  const [restoreSeed, setRestoreSeed]   = useState("");
  const [password, setPassword]         = useState("");
  const [confirmPwd, setConfirmPwd]     = useState("");
  const [showSeed, setShowSeed]         = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const words = seed.split(/\s+/).filter(Boolean);

  const confirmOk = checkIdxs.every(i => (confirmWords[i]||"").trim().toLowerCase() === words[i]);
  const pwdOk = password.length >= 8 && password === confirmPwd;

  function finish(markSeed = false) {
    markWalletCreated();
    if (markSeed) markSeedBackedUp();
    onComplete();
  }

  function buildCheckIndices(wordCount) {
    const checks = Math.min(3, Math.max(1, wordCount));
    const idxs = new Set();
    const rng = new Uint32Array(32);
    crypto.getRandomValues(rng);
    let i = 0;
    while (idxs.size < checks && i < rng.length) {
      idxs.add(rng[i++] % wordCount);
    }
    return [...idxs].sort((a,b)=>a-b);
  }

  async function handleCreateWallet() {
    if (!pwdOk || busy) return;
    setBusy(true);
    setErr("");
    try {
      const phrase = await rpc.createWallet(password);
      const normalized = String(phrase || "").trim().replace(/\s+/g, " ");
      const wc = normalized ? normalized.split(" ").length : 0;
      if (wc < 12) throw new Error("Wallet backend returned an invalid seed phrase");
      setSeed(normalized);
      setCheckIdxs(buildCheckIndices(wc));
      setShowSeed(false);
      setStep("backup");
    } catch (e) {
      setErr(String(e || "Failed to create wallet"));
    } finally {
      setBusy(false);
    }
  }

  async function handleRestoreWallet() {
    const normalized = restoreSeed.trim().replace(/\s+/g, " ");
    const wc = normalized ? normalized.split(" ").length : 0;
    if (wc < 12 || password.length < 8 || busy) return;
    setBusy(true);
    setErr("");
    try {
      await rpc.restoreWallet(normalized, password);
      markSeedBackedUp();
      finish(false);
    } catch (e) {
      setErr(String(e || "Restore failed"));
    } finally {
      setBusy(false);
    }
  }

  const box = {
    background:T.bg, borderRadius:14, padding:"32px 36px", width:480,
    border:`1px solid ${T.b}`, boxShadow:`0 20px 60px ${T.shadow}`,
  };

  if (step === "choose") return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg }}>
      <div style={{ textAlign:"center" }}>
        <CoinLogo size={72} style={{ margin:"0 auto 20px" }}/>
        <h1 style={{ fontSize:24, fontWeight:700, marginBottom:8 }}>CoinCync Wallet</h1>
        <p style={{ fontSize:13, color:T.t2, marginBottom:32 }}>Private by law. Private by math. · v1.0</p>
        <div style={{ display:"flex", gap:12 }}>
          <div onClick={()=>setStep("create")} style={{ padding:"20px 28px", border:`1px solid ${T.b}`,
            borderRadius:12, background:T.card, cursor:"pointer", textAlign:"left", width:200,
            transition:"border .15s" }}
            onMouseEnter={e=>e.currentTarget.style.borderColor=T.teal}
            onMouseLeave={e=>e.currentTarget.style.borderColor=T.b}>
            <Ico d={ICONS.unlock} size={20} color={T.teal}/>
            <div style={{ fontSize:14, fontWeight:600, marginTop:8, marginBottom:4 }}>Create New Wallet</div>
            <div style={{ fontSize:11, color:T.t3 }}>Generate a new seed phrase from backend wallet CLI</div>
          </div>
          <div onClick={()=>setStep("restore")} style={{ padding:"20px 28px", border:`1px solid ${T.b}`,
            borderRadius:12, background:T.card, cursor:"pointer", textAlign:"left", width:200,
            transition:"border .15s" }}
            onMouseEnter={e=>e.currentTarget.style.borderColor=T.blue}
            onMouseLeave={e=>e.currentTarget.style.borderColor=T.b}>
            <Ico d={ICONS.refresh} size={20} color={T.blue}/>
            <div style={{ fontSize:14, fontWeight:600, marginTop:8, marginBottom:4 }}>Restore Wallet</div>
            <div style={{ fontSize:11, color:T.t3 }}>Enter an existing seed phrase</div>
          </div>
        </div>
      </div>
    </div>
  );

  if (step === "create") return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg }}>
      <div style={{ ...box }}>
        <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:20 }}>
          <CoinLogo size={32}/><h2 style={{ fontSize:18, fontWeight:700 }}>Create Wallet</h2>
        </div>
        <div style={{ padding:"12px 14px", background:`${T.amber}12`, border:`1px solid ${T.amber}30`,
          borderRadius:8, marginBottom:16, fontSize:11, color:T.amber, display:"flex", gap:8 }}>
          <Ico d={ICONS.warning} size={13} color={T.amber}/>
          Your seed phrase will be generated by the wallet backend after password setup. Write it on paper only.
        </div>
        <Input label="Wallet Password (min 8 chars)" value={password} onChange={e=>setPassword(e.target.value)}
          type="password" placeholder="Strong password..."/>
        <div style={{ marginTop:10, marginBottom:16 }}>
          <Input label="Confirm Password" value={confirmPwd} onChange={e=>setConfirmPwd(e.target.value)}
            type="password" placeholder="Repeat password..."
            error={confirmPwd&&!pwdOk?"Passwords don't match":""}/>
        </div>
        {err && <div style={{ fontSize:11, color:T.red, marginBottom:12 }}>{err}</div>}
        <div style={{ display:"flex", gap:8 }}>
          <Btn variant="ghost" onClick={()=>setStep("choose")}>Back</Btn>
          <Btn onClick={handleCreateWallet} disabled={!pwdOk||busy} full>
            {busy ? "Generating..." : "Generate Seed Phrase →"}
          </Btn>
        </div>
      </div>
    </div>
  );

  if (step === "backup") return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg }}>
      <div style={{ ...box }}>
        <h2 style={{ fontSize:18, fontWeight:700, marginBottom:6 }}>Confirm Your Seed</h2>
        <p style={{ fontSize:12, color:T.t2, marginBottom:20 }}>
          Write down your {words.length}-word seed phrase, then enter words #{checkIdxs.map(i=>i+1).join(", ")}.
        </p>
        <div style={{ position:"relative", marginBottom:16 }}>
          {!showSeed && (
            <div onClick={()=>setShowSeed(true)} style={{ position:"absolute", inset:0, background:`${T.bg}cc`,
              borderRadius:8, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center",
              cursor:"pointer", zIndex:2 }}>
              <Ico d={ICONS.eye} size={24} color={T.teal}/>
              <div style={{ fontSize:12, color:T.teal, marginTop:8 }}>Click to reveal seed phrase</div>
            </div>
          )}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:6,
            padding:12, background:T.bg, borderRadius:8, border:`1px solid ${T.b}` }}>
            {words.map((w,i) => (
              <div key={i} style={{ background:T.card, border:`1px solid ${T.b}`, borderRadius:6,
                padding:"5px 7px", fontSize:10, fontFamily:"'JetBrains Mono',monospace" }}>
                <span style={{ color:T.t3, fontSize:8 }}>{i+1}. </span>
                <span style={{ color:T.t1 }}>{w}</span>
              </div>
            ))}
          </div>
        </div>
        <div style={{ display:"flex", flexDirection:"column", gap:12, marginBottom:20 }}>
          {checkIdxs.map(i => (
            <Input key={i} label={`Word #${i+1}`}
              value={confirmWords[i]||""}
              onChange={e=>setConfirmWords(w=>({...w,[i]:e.target.value}))}
              placeholder={`Enter word ${i+1}...`} mono
              error={confirmWords[i]&&confirmWords[i].trim().toLowerCase()!==words[i]?"Incorrect word":""}/>
          ))}
        </div>
        <div style={{ display:"flex", gap:8 }}>
          <Btn variant="ghost" onClick={()=>setStep("create")}>Back</Btn>
          <Btn onClick={()=>{finish(true);}} disabled={!confirmOk} full>
            <Ico d={ICONS.check} size={14} color="#000"/> Confirm & Open Wallet
          </Btn>
        </div>
      </div>
    </div>
  );

  if (step === "restore") return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:"100vh", background:T.bg }}>
      <div style={{ ...box }}>
        <h2 style={{ fontSize:18, fontWeight:700, marginBottom:6 }}>Restore Wallet</h2>
        <p style={{ fontSize:12, color:T.t2, marginBottom:16 }}>Enter your seed phrase (24 words typical), space-separated or one per line.</p>
        <div style={{ marginBottom:12 }}>
          <textarea value={restoreSeed} onChange={e=>setRestoreSeed(e.target.value)}
            placeholder="word1 word2 word3..." rows={5}
            style={{ background:T.inputBg, border:`1px solid ${T.b}`, borderRadius:7, color:T.t1,
              fontFamily:"'JetBrains Mono',monospace", fontSize:12, padding:"10px 12px",
              width:"100%", outline:"none", resize:"vertical" }}/>
          <div style={{ fontSize:9, color:T.t3, marginTop:3 }}>
            Words entered: {restoreSeed.trim().split(/\s+/).filter(Boolean).length}
          </div>
        </div>
        <Input label="Wallet Password" value={password} onChange={e=>setPassword(e.target.value)}
          type="password" placeholder="Set a new password..."/>
        {err && <div style={{ fontSize:11, color:T.red, marginTop:10 }}>{err}</div>}
        <div style={{ display:"flex", gap:8, marginTop:16 }}>
          <Btn variant="ghost" onClick={()=>setStep("choose")}>Back</Btn>
          <Btn
            onClick={handleRestoreWallet}
            disabled={restoreSeed.trim().split(/\s+/).filter(Boolean).length<12 || password.length<8 || busy}
            full
          >
            {busy ? "Restoring..." : "Restore Wallet"}
          </Btn>
        </div>
      </div>
    </div>
  );

  return null;
}
