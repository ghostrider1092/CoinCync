import { useState } from "react";
import { useTheme, Ico, ICONS } from "../components/ui";
import Constitution from "./Compliance";
import Privacy from "./Privacy";
import Audit from "./Audit";

const TABS = [
  { id: "constitution", label: "Constitution", icon: "constitution",
    sub: "The 6 articles. Code-enforced governance.", Comp: Constitution },
  { id: "privacy",      label: "Privacy",      icon: "privacy",
    sub: "22 features across 4 layers.",            Comp: Privacy },
  { id: "audit",        label: "Supply Audit",  icon: "shield",
    sub: "Live supply + integrity checks.",          Comp: Audit },
];

export default function Transparency() {
  const T = useTheme();
  const [active, setActive] = useState("constitution");
  const tab = TABS.find(t => t.id === active) || TABS[0];
  const Active = tab.Comp;

  return (
    <div style={{ animation:"fadeIn .2s ease" }}>
      <div style={{ marginBottom:18 }}>
        <h1 style={{ fontFamily:T.serif, fontSize:21, fontWeight:400 }}>Transparency</h1>
        <p style={{ fontSize:11, color:T.t3, marginTop:3 }}>
          Constitution, privacy architecture, and live supply audit — everything that makes the chain auditable in one place.
        </p>
      </div>

      <div style={{ display:"flex", gap:6, padding:6, background:T.card,
        border:`1px solid ${T.b}`, borderRadius:12, marginBottom:20 }}>
        {TABS.map(t => {
          const isActive = t.id === active;
          return (
            <button key={t.id} onClick={() => setActive(t.id)} style={{
              flex:1, display:"flex", alignItems:"center", gap:10,
              padding:"10px 14px", borderRadius:8, border:"none", cursor:"pointer",
              background: isActive ? `linear-gradient(135deg, ${T.ac2}18, ${T.ac2}08)` : "transparent",
              color: isActive ? T.ac2 : T.t2,
              transition:"all .15s",
              borderLeft: isActive ? `3px solid ${T.ac2}` : "3px solid transparent",
              textAlign:"left",
            }}
              onMouseEnter={e=>{ if(!isActive){ e.currentTarget.style.background = `${T.ac2}08`; e.currentTarget.style.color = T.t1; } }}
              onMouseLeave={e=>{ if(!isActive){ e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = T.t2; } }}>
              <Ico d={ICONS[t.icon] || ICONS.info} size={16} color={isActive ? T.ac2 : T.t3}/>
              <div>
                <div style={{ fontSize:12, fontWeight: isActive ? 600 : 500 }}>{t.label}</div>
                <div style={{ fontSize:10, color:T.t3, marginTop:1 }}>{t.sub}</div>
              </div>
            </button>
          );
        })}
      </div>

      <div key={active} style={{ animation:"fadeIn .2s ease" }}>
        <Active/>
      </div>
    </div>
  );
}
