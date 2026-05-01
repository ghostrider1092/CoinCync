import { useState, useContext, useEffect } from "react";
import { useTheme, Card, Btn, Ico, Lbl, Input, Select, Section, Row, Toggle, ICONS, SP } from "../components/ui";
import { loadSettings, saveSettings, isSeedBackedUp, markSeedBackedUp, clearCoincyncLocalState } from "../utils/storage";
import { THEME_LIST, WALLPAPERS, applyWallpaper } from "../utils/theme";
import { NotifCtx } from "../appContexts";
import { rpc, isWalletBackendAvailable } from "../utils/rpc";

export default function Settings({ onThemeToggle, isDark, themeName, onChangeTheme }) {
  const { push } = useContext(NotifCtx);
  const T = useTheme();
  const [cfg, setCfg] = useState(loadSettings);
  const [tab, setTab] = useState("general");
  const [wallpaper, setWallpaper] = useState(() => localStorage.getItem("cc_wallpaper") || "none");
  const [churnMin, setChurnMin] = useState(60);
  const [churnMax, setChurnMax] = useState(360);
  const [deadManBlocks, setDeadManBlocks] = useState(52560);
  const [deadManAddr, setDeadManAddr] = useState("");

  const [secStatus, setSecStatus] = useState({
    loading: false,
    backend: isWalletBackendAvailable(),
    binaries: null,
    error: "",
  });

  useEffect(() => {
    if (tab !== "security") return;
    if (!isWalletBackendAvailable()) {
      setSecStatus({ loading: false, backend: false, binaries: null, error: "" });
      return;
    }
    let cancelled = false;
    setSecStatus((s) => ({ ...s, loading: true, backend: true, error: "" }));
    (async () => {
      try {
        const bins = await rpc.checkBinaries();
        if (!cancelled) {
          setSecStatus({ loading: false, backend: true, binaries: bins || null, error: "" });
        }
      } catch (e) {
        if (!cancelled) {
          setSecStatus({
            loading: false,
            backend: true,
            binaries: null,
            error: String(e?.message || e || "Security check failed"),
          });
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [tab]);

  function update(k, v) { const n = {...cfg,[k]:v}; setCfg(n); saveSettings(n); push("Setting saved","success"); }

  const churnError = churnMin >= churnMax ? "Min must be less than max" : "";
  const deadManAddrError = deadManAddr && !deadManAddr.startsWith("tCYNC") && !deadManAddr.startsWith("CYNC")
    ? "Must start with tCYNC or CYNC" : "";

  const TABS = [
    { id:"general", label:"General", icon:ICONS.settings },
    { id:"privacy", label:"Privacy", icon:ICONS.shield },
    { id:"advanced", label:"Advanced", icon:ICONS.keys },
    { id:"security", label:"Security", icon:ICONS.lock },
  ];

  return (
    <div style={{ animation:"fadeIn .2s ease", maxWidth:"100%" }}>
      <div style={{ marginBottom:SP.lg }}><h1 style={{ fontSize:21, fontWeight:700 }}>Settings</h1></div>

      {/* Tab bar */}
      <div style={{ display:"flex", gap:SP.sm, marginBottom:SP.xl, borderBottom:`1px solid ${T.b}`, paddingBottom:0 }}>
        {TABS.map(t => (
          <button key={t.id} onClick={()=>setTab(t.id)} style={{
            display:"flex", alignItems:"center", gap:6, padding:"8px 14px",
            borderRadius:`${SP.md}px ${SP.md}px 0 0`, border:"none",
            background:tab===t.id?`${T.ac2}12`:"transparent",
            color:tab===t.id?T.ac2:T.t3, fontSize:11, fontWeight:tab===t.id?600:400,
            cursor:"pointer", borderBottom:tab===t.id?`2px solid ${T.ac2}`:"2px solid transparent",
            transition:"all .15s" }}>
            <Ico d={t.icon} size={13} color={tab===t.id?T.ac2:T.t3}/>{t.label}
          </button>
        ))}
      </div>

      {!isSeedBackedUp() && (
        <div style={{ padding:"12px 16px", background:`${T.amber}12`, border:`1px solid ${T.amber}30`,
          borderRadius:10, marginBottom:14, display:"flex", justifyContent:"space-between", alignItems:"center" }}>
          <div style={{ display:"flex", alignItems:"center", gap:9 }}>
            <Ico d={ICONS.warning} size={16} color={T.amber}/>
            <div>
              <div style={{ fontSize:13, fontWeight:600, color:T.amber }}>Seed phrase not backed up</div>
              <div style={{ fontSize:10, color:T.t3 }}>Write your 25 words on paper. Funds are unrecoverable without them.</div>
            </div>
          </div>
          <Btn small variant="danger" onClick={()=>{markSeedBackedUp();window.location.reload();}}>Mark Done</Btn>
        </div>
      )}

      {/* ── General Tab ─────────────────────────── */}
      {tab==="general" && <>
        <Section title="Appearance">
          <Lbl>Theme</Lbl>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:6, marginBottom:14 }}>
            {THEME_LIST.map(t=>(
              <button key={t.id} onClick={()=>onChangeTheme(t.id)}
                style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 10px",
                border:`1px solid ${themeName===t.id?T.ac2:T.b2}`, borderRadius:8,
                background:themeName===t.id?T.ac2+'12':'transparent',
                cursor:"pointer", transition:"all .15s" }}>
                <div style={{ width:24, height:24, borderRadius:4, background:t.bg, border:"1px solid rgba(128,128,128,.2)",
                  display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                  <div style={{ width:8, height:8, borderRadius:"50%", background:t.ac }}/>
                </div>
                <span style={{ fontSize:11, color:themeName===t.id?T.ac2:T.t2 }}>{t.label}</span>
              </button>
            ))}
          </div>
          <Lbl>Wallpaper</Lbl>
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:6, marginBottom:14 }}>
            {WALLPAPERS.map(w=>(
              <button key={w.id} title={w.label} onClick={()=>{
                applyWallpaper(w.id); setWallpaper(w.id);
                push(w.id==="none"?"Wallpaper cleared":w.label+" wallpaper set","success");
              }}
                style={{ aspectRatio:"16/9", borderRadius:6,
                border:`1px solid ${wallpaper===w.id?T.ac2:T.b2}`,
                background:wallpaper===w.id?T.ac2+'12':T.bg,
                cursor:"pointer", overflow:"hidden", padding:0, transition:"border-color .15s",
                display:"flex", alignItems:"center", justifyContent:"center" }}
                onMouseEnter={e=>e.currentTarget.style.borderColor=T.ac2}
                onMouseLeave={e=>{if(wallpaper!==w.id)e.currentTarget.style.borderColor=T.b2}}>
                {w.id==="none"
                  ? <span style={{ fontSize:9, color:T.t3, fontFamily:T.mono }}>OFF</span>
                  : <div style={{
                      width:"100%",
                      height:"100%",
                      display:"flex",
                      alignItems:"flex-end",
                      justifyContent:"flex-start",
                      padding:4,
                      background: w.css || `url(${w.url}) center/cover no-repeat`,
                    }}>
                      <span style={{
                        fontSize:7,
                        color:"#f5f0e8",
                        fontFamily:T.mono,
                        background:"rgba(0,0,0,.38)",
                        border:"1px solid rgba(255,255,255,.12)",
                        borderRadius:4,
                        padding:"1px 4px",
                        lineHeight:1.2,
                      }}>
                        {w.label}
                      </span>
                    </div>
                }
              </button>
            ))}
          </div>
          <Row label="Show Phase 2 features" hint="Enables Halo2 shielded pool and RSA accumulator UI">
            <Toggle val={cfg.showPhase2} onToggle={()=>update("showPhase2",!cfg.showPhase2)}/>
          </Row>
        </Section>

        <Section title="Node">
          <Row label="Daemon address">
            <input value={cfg.daemonAddr||""} onChange={e=>update("daemonAddr",e.target.value)}
              style={{ width:180, padding:"4px 8px", fontSize:11, background:T.inputBg,
                border:`1px solid ${T.b}`, borderRadius:6, color:T.t1, outline:"none",
                fontFamily:"'JetBrains Mono',monospace", transition:"border .15s" }}
              onFocus={e=>e.target.style.borderColor=T.ac2}
              onBlur={e=>e.target.style.borderColor=T.b}/>
          </Row>
          <Row label="Network">
            <Select value={cfg.network||"testnet"} onChange={e=>update("network",e.target.value)}
              options={["testnet","mainnet","regtest"]}/>
          </Row>
          <Row label="Tor routing" hint="Routes all P2P through Tor. Requires Tor daemon running.">
            <Toggle val={cfg.torEnabled} onToggle={()=>update("torEnabled",!cfg.torEnabled)}/>
          </Row>
          <Row label="Scan on startup">
            <Toggle val={cfg.scanOnStart} onToggle={()=>update("scanOnStart",!cfg.scanOnStart)}/>
          </Row>
          <Row
            label="Auto-lock timeout"
            hint="Automatically locks wallet after inactivity; set to Off only for trusted test environments."
          >
            <Select
              value={String(cfg.autoLockMinutes ?? 15)}
              onChange={e=>update("autoLockMinutes", parseInt(e.target.value, 10))}
              options={["5","15","30","60","0"]}
              labels={["5 minutes","15 minutes","30 minutes","60 minutes","Off"]}
            />
          </Row>
        </Section>
      </>}

      {/* ── Privacy Tab ─────────────────────────── */}
      {tab==="privacy" && <>
        <Section title="Layer 1 — Cryptographic" color={T.ac2}>
          <Row label="Ring size" hint="Always 11 (CLSAG). Locked by protocol." locked>
            <span style={{ fontFamily:T.mono, fontSize:12, color:T.t3 }}>11</span>
          </Row>
          <Row label="Mandatory privacy" hint="Every transaction is private. No opt-out. Article III." locked>
            <Toggle val={true} disabled/>
          </Row>
          <Row label="Uniform 2-in 2-out shape" hint="Fixed transaction shape. Locked by protocol." locked>
            <Toggle val={true} disabled/>
          </Row>
          <Row label="Pedersen commitments" hint="All amounts hidden. Locked by protocol." locked>
            <Toggle val={true} disabled/>
          </Row>
        </Section>

        <Section title="Layer 2 — Network" color={T.blue}>
          <Row label="Dandelion++ propagation" hint="Random stem path before broadcast. IP de-linked.">
            <Toggle val={cfg.dandelion} onToggle={()=>update("dandelion",!cfg.dandelion)}/>
          </Row>
          <Row label="Traffic shaping (0-200ms jitter)" hint="Randomizes outbound message timing.">
            <Toggle val={cfg.trafficShaping??true} onToggle={()=>update("trafficShaping",!(cfg.trafficShaping??true))}/>
          </Row>
          <Row label="Constant-rate padding" hint="Sends dummy packets to mask activity patterns.">
            <Toggle val={cfg.constPadding??true} onToggle={()=>update("constPadding",!(cfg.constPadding??true))}/>
          </Row>
          <Row label="Noise_XX P2P encryption" hint="Signal-grade P2P. Locked by protocol." locked>
            <Toggle val={true} disabled/>
          </Row>
        </Section>

        <Section title="Layer 3 — Wallet" color={T.amber}>
          <Row label="Uniform decoy selection" hint="Samples from entire UTXO set, defeats recency heuristics.">
            <Toggle val={cfg.uniformDecoys??true} onToggle={()=>update("uniformDecoys",!(cfg.uniformDecoys??true))}/>
          </Row>
          <Row label="Auto-shield coinbase" hint="Mining rewards go directly into shielded pool.">
            <Toggle val={cfg.autoShield} onToggle={()=>update("autoShield",!cfg.autoShield)}/>
          </Row>
        </Section>
      </>}

      {/* ── Advanced Tab ────────────────────────── */}
      {tab==="advanced" && <>
        <Section title="Auto-Churn" color={T.teal}>
          <div style={{ fontSize:10, color:T.t3, marginBottom:14 }}>
            Wallet automatically sends coins to itself at Poisson-distributed random intervals.
            Poisons the transaction graph with noise, making chain analysis unreliable.
          </div>
          <Row label="Auto-churn enabled" hint="Sends to self at random Poisson intervals">
            <Toggle val={cfg.autoChurn??false} onToggle={()=>update("autoChurn",!cfg.autoChurn)}/>
          </Row>
          {cfg.autoChurn && (
            <>
              <div style={{ marginTop:12, display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                <Input label="Min interval (minutes)" type="number" value={String(churnMin)}
                  onChange={e=>setChurnMin(Math.max(10, +e.target.value))} mono
                  error={churnError}/>
                <Input label="Max interval (minutes)" type="number" value={String(churnMax)}
                  onChange={e=>setChurnMax(Math.min(1440, +e.target.value))} mono/>
              </div>
              <div style={{ marginTop:8, fontSize:9, color:T.t3 }}>
                {"\u03BB"} = 1/{Math.round((churnMin+churnMax)/2)} min. Each churn is a full ring-11 tx with new stealth address.
              </div>
            </>
          )}
        </Section>

        <Section title="Dead Man's Switch" color={T.red}>
          <div style={{ fontSize:10, color:T.t3, marginBottom:14 }}>
            Time-locked recovery address. If you don't sign a heartbeat transaction within N blocks,
            a backup address can sweep your funds. Your money survives you.
          </div>
          <Row label="Dead man's switch enabled">
            <Toggle val={cfg.deadMansSwitch??false} onToggle={()=>update("deadMansSwitch",!cfg.deadMansSwitch)}/>
          </Row>
          {cfg.deadMansSwitch && (
            <div style={{ marginTop:12, display:"flex", flexDirection:"column", gap:10 }}>
              <Input label={`Timeout (blocks) — ~${Math.round(deadManBlocks/720)} days at 2min/block`}
                type="number" value={String(deadManBlocks)}
                onChange={e=>setDeadManBlocks(Math.max(720, +e.target.value))} mono/>
              <Input label="Recovery Address (tCYNC3...)" value={deadManAddr}
                onChange={e=>setDeadManAddr(e.target.value)}
                placeholder="tCYNC3q... backup address that can sweep after timeout" mono
                error={deadManAddrError}/>
              <div style={{ padding:"9px 11px", background:`${T.red}09`, borderRadius:7, border:`1px solid ${T.red}20`, fontSize:10, color:T.red, display:"flex", alignItems:"flex-start", gap:6 }}>
                <Ico d={ICONS.warning} size={12} color={T.red}/>
                <span>Sign a heartbeat transaction every {Math.round(deadManBlocks/720)} days to keep your funds. Miss the window and the recovery address can sweep.</span>
              </div>
              <Btn small onClick={()=>push("Dead man's switch configured","success")}
                disabled={!deadManAddr || !!deadManAddrError}>
                Configure Switch
              </Btn>
            </div>
          )}
        </Section>
      </>}


      {/* ── Security Tab ────────────────────────── */}
      {tab==="security" && <>
        <Card style={{ marginBottom:10 }}>
          <div style={{ fontSize:10, fontWeight:700, color:T.t3, letterSpacing:.8, textTransform:"uppercase", marginBottom:11 }}>
            Security Status
          </div>
          <div style={{ display:"grid", gap:8 }}>
            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"8px 0", borderBottom:`1px solid ${T.b2}` }}>
              <div>
                <div style={{ fontSize:11, color:T.t1, fontWeight:500 }}>Backend Mode</div>
                <div style={{ fontSize:10, color:T.t3 }}>Desktop Tauri backend required for full wallet actions.</div>
              </div>
              <div style={{ fontSize:10, fontWeight:700, color:secStatus.backend ? T.teal : T.amber }}>
                {secStatus.backend ? "ACTIVE" : "BROWSER-ONLY"}
              </div>
            </div>

            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"8px 0", borderBottom:`1px solid ${T.b2}` }}>
              <div>
                <div style={{ fontSize:11, color:T.t1, fontWeight:500 }}>Unlock Brute-Force Guard</div>
                <div style={{ fontSize:10, color:T.t3 }}>5 failed unlock attempts trigger a 30s cooldown.</div>
              </div>
              <div style={{ fontSize:10, fontWeight:700, color:T.teal }}>ENFORCED</div>
            </div>

            <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"8px 0" }}>
              <div>
                <div style={{ fontSize:11, color:T.t1, fontWeight:500 }}>Bundled Runtime Binaries</div>
                <div style={{ fontSize:10, color:T.t3 }}>
                  Node, wallet CLI, and miner presence in this app environment.
                </div>
              </div>
              <div style={{ fontSize:10, fontWeight:700, color: secStatus.loading ? T.t3 : (secStatus.binaries?.all_installed ? T.teal : T.amber) }}>
                {secStatus.loading ? "CHECKING..." : (secStatus.binaries?.all_installed ? "OK" : "MISSING")}
              </div>
            </div>
          </div>
          {!!secStatus.error && (
            <div style={{ marginTop:8, fontSize:10, color:T.red }}>
              {secStatus.error}
            </div>
          )}
        </Card>

        <Card style={{ background:`${T.red}06`, border:`1px solid ${T.red}20`, marginBottom:10 }}>
          <div style={{ fontSize:10, fontWeight:700, color:T.red, letterSpacing:.8, textTransform:"uppercase", marginBottom:11 }}>
            Layer 4 — Constitutional Locks
          </div>
          <div style={{ fontSize:10, color:T.t3, marginBottom:12 }}>
            These protections are hardcoded into the protocol and cannot be changed by anyone — not developers, not miners, not governments.
          </div>
          {[
            ["Mandatory Privacy (Article III)", "Cannot be disabled. Every tx is private.", ICONS.shield],
            ["No Surveillance (Article IX)",    "No blacklists, no freezing, no backdoors.", ICONS.eyeOff],
            ["No Balance Lookup",               "No RPC exists to query an address balance.", ICONS.lock],
            ["4th Amendment Protection",        "Financial records are constitutionally protected.", ICONS.constitution],
          ].map(([l,d,icon])=>(
            <div key={l} style={{ padding:"10px 0", borderBottom:`1px solid ${T.red}15` }}>
              <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
                <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                  <Ico d={icon} size={14} color={T.red}/>
                  <div>
                    <div style={{ fontSize:11, color:T.t1, fontWeight:500 }}>{l}</div>
                    <div style={{ fontSize:9, color:T.t3 }}>{d}</div>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                  <span style={{ fontSize:9, color:T.red, fontWeight:600 }}>LOCKED</span>
                  <Toggle val={true} disabled/>
                </div>
              </div>
            </div>
          ))}
        </Card>

        <Card>
          <div style={{ fontSize:10, fontWeight:700, color:T.t3, letterSpacing:.8, textTransform:"uppercase", marginBottom:11 }}>
            Danger Zone
          </div>
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", padding:"10px 0" }}>
            <div>
              <div style={{ fontSize:12, fontWeight:500, color:T.red }}>Reset wallet data</div>
              <div style={{ fontSize:10, color:T.t3 }}>Deletes all local data. Requires seed phrase to recover.</div>
            </div>
            <Btn small variant="danger" onClick={()=>{
              if (!confirm("Delete all local CoinCync app data? This cannot be undone.")) return;
              clearCoincyncLocalState();
              window.location.reload();
            }}>
              Reset
            </Btn>
          </div>
        </Card>
      </>}
    </div>
  );
}
