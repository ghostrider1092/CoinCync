import { useEffect } from "react";
import { useTheme, Ico, ICONS, RAD, SP } from "./ui";

export default function Notifications({ notifs, dismiss }) {
  const T = useTheme();
  const COLORS = { info:T.blue, success:T.green||T.ac2, error:T.red, warning:T.amber };

  // Escape key dismisses most recent notification
  useEffect(() => {
    if (notifs.length === 0) return;
    const handler = (e) => { if (e.key === "Escape") dismiss(notifs[notifs.length-1].id); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [notifs, dismiss]);

  // Only show latest 4 notifications to prevent stack overflow
  const visible = notifs.slice(-4);

  return (
    <div role="log" aria-live="polite" style={{ position:"fixed", top:SP.xl, right:SP.xl, zIndex:9999,
      display:"flex", flexDirection:"column", gap:SP.md }}>
      {visible.map((n, i) => (
        <div key={n.id} style={{ background:T.card, border:`1px solid ${(COLORS[n.type]||COLORS.info)}40`,
          borderRadius:RAD.lg-2, padding:`${SP.lg}px ${SP.xl}px`, display:"flex", alignItems:"center", gap:SP.lg-2,
          minWidth:280, maxWidth:360, boxShadow:`0 4px 20px ${T.shadow}`,
          animation:"notif .25s ease",
          opacity: i < visible.length - 4 ? 0.6 : 1,
          transition:"opacity .2s" }}>
          <div style={{ width:28, height:28, borderRadius:RAD.md, flexShrink:0,
            background:`${(COLORS[n.type]||COLORS.info)}15`,
            display:"flex", alignItems:"center", justifyContent:"center" }}>
            <Ico d={n.type==="success"?ICONS.check:n.type==="error"?ICONS.close:n.type==="warning"?ICONS.warning:ICONS.info}
              size={14} color={COLORS[n.type]||COLORS.info}/>
          </div>
          <span style={{ flex:1, fontSize:12, color:T.t1 }}>{n.message}</span>
          <button onClick={()=>dismiss(n.id)} style={{ background:"none", border:"none", color:T.t3,
            cursor:"pointer", padding:4, borderRadius:RAD.sm, transition:"background .12s" }}
            onMouseEnter={e=>e.currentTarget.style.background=T.b}
            onMouseLeave={e=>e.currentTarget.style.background="none"}>
            <Ico d={ICONS.close} size={13}/>
          </button>
        </div>
      ))}
    </div>
  );
}
