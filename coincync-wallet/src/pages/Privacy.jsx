import { useState } from "react";
import { useTheme, Card, Badge, Ico, Divider, ICONS } from "../components/ui";

const layers = [
  {
    id: "l1",
    title: "Layer 1 — Cryptographic Privacy",
    sub: "On-chain · embedded in every transaction",
    color: "#00d4aa",
    icon: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
    features: [
      { name:"CLSAG Ring Signatures", icon:"M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8zM23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75", detail:"Hides real sender among 11 decoys. Nobody can tell which input was actually spent.", badge:"Ring 11", color:"#00d4aa" },
      { name:"Stealth Addresses (Ristretto255)", icon:"M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 9a3 3 0 100 6 3 3 0 000-6z", detail:"Every transaction creates a one-time destination via ECDH. Your real address never appears on-chain.", badge:"1-time addr", color:"#00d4aa" },
      { name:"Pedersen Commitments", icon:"M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5", detail:"Amounts are hidden inside cryptographic commitments. The chain proves they balance without revealing values.", badge:"Hidden amounts", color:"#00d4aa" },
      { name:"Bulletproofs+ Range Proofs", icon:"M13 2L3 14h9l-1 8 10-12h-9l1-8z", detail:"Proves each hidden amount is in [0, 2^64) without revealing the number. Prevents negative-value inflation attacks.", badge:"0..2^64", color:"#00d4aa" },
      { name:"Encrypted Memos (ChaCha20+ECDH)", icon:"M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z", detail:"Optional message field encrypted with the recipient's key. Only sender and receiver can read it.", badge:"512 bytes", color:"#2d8cf0" },
      { name:"View Tags", icon:"M15 12a3 3 0 11-6 0 3 3 0 016 0z", detail:"1-byte optimization: wallets skip 99.6% of outputs during scanning with zero information leak.", badge:"99.6% skip", color:"#2d8cf0" },
      { name:"Key Images", icon:"M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3", detail:"Prevents double-spending without revealing which output was spent. Each output produces exactly one unique key image.", badge:"Anti double-spend", color:"#2ecc8a" },
    ]
  },
  {
    id: "l2",
    title: "Layer 2 — Network Privacy",
    sub: "Off-chain · transport and propagation",
    color: "#2d8cf0",
    icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    features: [
      { name:"Dandelion++ Propagation", icon:"M22 12h-4l-3 9L9 3l-3 9H2", detail:"Transactions relay through a random stem path before broadcast. ISPs cannot correlate your IP to your transaction.", badge:"IP hidden", color:"#2d8cf0" },
      { name:"Noise_XX Encrypted P2P", icon:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", detail:"All peer connections use the Noise protocol (same as Signal/WhatsApp). ISPs cannot read P2P traffic.", badge:"Signal-grade", color:"#2d8cf0" },
      { name:"Traffic Shaping", icon:"M23 7l-7 5 7 5V7zM1 17h14V7H1v10z", detail:"Timing jitter of 0–200ms on all outbound messages defeats traffic correlation analysis.", badge:"0–200ms jitter", color:"#f5a623" },
      { name:"Constant-Rate Padding", icon:"M18 8h1a4 4 0 010 8h-1M2 8h16v9a4 4 0 01-4 4H6a4 4 0 01-4-4V8zM6 1v3M10 1v3M14 1v3", detail:"Dummy packets sent at regular intervals. Observers cannot distinguish idle nodes from active ones.", badge:"Dummy packets", color:"#f5a623" },
    ]
  },
  {
    id: "l3",
    title: "Layer 3 — Wallet Privacy",
    sub: "User-side · spending and key management",
    color: "#f5a623",
    icon: "M3 10h18M7 15h1m4 0h1m-7 4h12a3 3 0 003-3V8a3 3 0 00-3-3H6a3 3 0 00-3 3v8a3 3 0 003 3z",
    features: [
      { name:"Uniform Decoy Selection", icon:"M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2", detail:"Ring members chosen uniformly across the entire UTXO set. Defeats chain-analysis heuristics that exploit recency bias.", badge:"Anti-heuristic", color:"#f5a623" },
      { name:"Time-Scoped View Keys", icon:"M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z", detail:"Export a view key that only decrypts outputs from a specific block range. Auditors see only what you allow.", badge:"Block range", color:"#f5a623" },
      { name:"Plausible Deniability Wallets", icon:"M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4", detail:"Dual-password encryption. One password opens a decoy wallet, the other opens the real one. Same file, cryptographically indistinguishable.", badge:"Dual password", color:"#f5a623" },
      { name:"Auto-Churn", icon:"M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15", detail:"Wallet automatically sends coins to itself at Poisson-distributed random intervals, poisoning the transaction graph with noise.", badge:"Poisson intervals", color:"#f5a623" },
      { name:"Dead Man's Switch", icon:"M12 8v4l3 3M3.05 11a9 9 0 1 0 .5-4.5", detail:"Time-locked recovery address. If you don't sign for N blocks, a backup address can sweep your funds.", badge:"Time-locked", color:"#e84545" },
      { name:"Uniform Transaction Shape", icon:"M4 6h16M4 12h16M4 18h16", detail:"All transfers have exactly 2 inputs and 2 outputs. Transaction types cannot be fingerprinted by their shape.", badge:"2-in 2-out", color:"#f5a623" },
      { name:"FROST Multi-Sig", icon:"M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8zM23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75", detail:"Threshold signatures indistinguishable from single-sig on-chain. Nobody can tell a 2-of-3 multisig from a normal transaction.", badge:"Threshold", color:"#2d8cf0" },
    ]
  },
  {
    id: "l4",
    title: "Layer 4 — Constitutional Privacy",
    sub: "Governance · protocol-level guarantees",
    color: "#e84545",
    icon: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM9 12l2 2 4-4",
    features: [
      { name:"Mandatory Privacy (Article III)", icon:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z", detail:"Every transaction MUST be private. No opt-out, no transparent mode, no t-addresses. The entire anonymity set is always the entire chain.", badge:"No opt-out", color:"#e84545" },
      { name:"No Surveillance Infrastructure (Article IX)", icon:"M18 6L6 18M6 6l12 12", detail:"No blacklists, no address freezing, no censorship hooks, no compliance backdoors. The code physically cannot do these things.", badge:"Code-enforced", color:"#e84545" },
      { name:"No Balance Lookup", icon:"M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8", detail:"No RPC method exists to query an address balance. No rich list. No address history. The chain cannot leak what it doesn't store in readable form.", badge:"No rich list", color:"#e84545" },
      { name:"4th Amendment Foundation", icon:"M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8zM14 2v6h6", detail:"The Constitution explicitly recognizes financial records as 'papers and effects' protected against unreasonable search.", badge:"Constitutional", color:"#e84545" },
    ]
  },
];

export default function Privacy() {
  const T = useTheme();
  const [open, setOpen] = useState({ l1:true, l2:false, l3:false, l4:false });
  const toggle = id => setOpen(o => ({...o, [id]: !o[id]}));
  const totalFeatures = layers.reduce((a, l) => a + l.features.length, 0);

  return (
    <div style={{ animation:"fadeIn .2s ease" }}>
      <div style={{ marginBottom:20 }}>
        <h1 style={{ fontSize:21, fontWeight:700 }}>Privacy Architecture</h1>
        <p style={{ fontSize:11, color:T.t3, marginTop:3 }}>
          {totalFeatures} privacy features across 4 independent layers
        </p>
        <p style={{ fontSize:10, color:T.t3, marginTop:6 }}>
          Protocol-enforced features and wallet UX capabilities are listed together; some wallet-side items are operational features and not consensus rules.
        </p>
      </div>

      {/* Summary cards */}
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:18 }}>
        {layers.map(l => (
          <div key={l.id} onClick={() => toggle(l.id)} style={{ background:T.card, border:`1px solid ${open[l.id]?l.color:T.b}`,
            borderRadius:11, padding:"14px 16px", cursor:"pointer", transition:"border .15s",
            boxShadow: open[l.id]?`0 0 16px ${l.color}18`:"none" }}>
            <div style={{ width:30, height:30, borderRadius:8, background:`${l.color}18`,
              display:"flex", alignItems:"center", justifyContent:"center", marginBottom:8 }}>
              <Ico d={l.icon} size={15} color={l.color}/>
            </div>
            <div style={{ fontSize:10, fontWeight:700, color:l.color, letterSpacing:.5 }}>
              {l.title.split("—")[0].trim()}
            </div>
            <div style={{ fontSize:11, fontWeight:600, marginTop:2, color:T.t1 }}>
              {l.features.length} features
            </div>
            <div style={{ fontSize:9, color:T.t3, marginTop:1 }}>{l.sub.split("·")[0].trim()}</div>
          </div>
        ))}
      </div>

      {/* Layer panels */}
      {layers.map(l => (
        <Card key={l.id} style={{ marginBottom:12, padding:0, overflow:"hidden" }}>
          {/* Layer header */}
          <div onClick={() => toggle(l.id)} style={{ display:"flex", justifyContent:"space-between",
            alignItems:"center", padding:"16px 20px", cursor:"pointer",
            borderBottom: open[l.id]?`1px solid ${T.b}`:"none",
            background: open[l.id]?`${l.color}06`:"transparent" }}>
            <div style={{ display:"flex", alignItems:"center", gap:12 }}>
              <div style={{ width:36, height:36, borderRadius:9, background:`${l.color}18`,
                display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                <Ico d={l.icon} size={18} color={l.color}/>
              </div>
              <div>
                <div style={{ fontSize:14, fontWeight:700, color:T.t1 }}>{l.title}</div>
                <div style={{ fontSize:10, color:T.t3, marginTop:1 }}>{l.sub}</div>
              </div>
            </div>
            <div style={{ display:"flex", alignItems:"center", gap:10 }}>
              <Badge label={`${l.features.length} features`} color={l.color}/>
              <Ico d={open[l.id]?"M18 15l-6-6-6 6":"M6 9l6 6 6-6"} size={16} color={T.t3}/>
            </div>
          </div>

          {/* Feature list */}
          {open[l.id] && (
            <div>
              {l.features.map((f, i) => (
                <div key={f.name} style={{ display:"flex", alignItems:"flex-start", gap:14,
                  padding:"13px 20px", borderBottom: i < l.features.length-1?`1px solid ${T.b}`:"none",
                  transition:"background .1s" }}
                  onMouseEnter={e=>e.currentTarget.style.background=T.bg}
                  onMouseLeave={e=>e.currentTarget.style.background=""}>
                  <div style={{ width:32, height:32, borderRadius:8, background:`${f.color}15`,
                    display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, marginTop:1 }}>
                    <Ico d={f.icon} size={14} color={f.color}/>
                  </div>
                  <div style={{ flex:1 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:3 }}>
                      <span style={{ fontSize:12, fontWeight:600, color:T.t1 }}>{f.name}</span>
                      <Badge label={f.badge} color={f.color}/>
                    </div>
                    <div style={{ fontSize:11, color:T.t2, lineHeight:1.5 }}>{f.detail}</div>
                  </div>
                  <div style={{ width:6, height:6, borderRadius:"50%", background:f.color,
                    flexShrink:0, marginTop:6 }}/>
                </div>
              ))}
            </div>
          )}
        </Card>
      ))}

      {/* Constitutional footer */}
      <div style={{ padding:"14px 18px", background:`${T.red}08`, border:`1px solid ${T.red}20`,
        borderRadius:11, display:"flex", alignItems:"flex-start", gap:12 }}>
        <Ico d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM9 12l2 2 4-4" size={18} color={T.red}/>
        <div>
          <div style={{ fontSize:12, fontWeight:700, color:T.red, marginBottom:3 }}>
            Constitutional Guarantee
          </div>
          <div style={{ fontSize:11, color:T.t2, lineHeight:1.5 }}>
            Privacy is not a feature that can be disabled — it is a constitutional obligation.
            No version of this software can ever produce a transparent transaction, expose an address balance,
            or implement a surveillance backdoor. These protections are enforced at the code level,
            not the policy level.
          </div>
        </div>
      </div>
    </div>
  );
}
