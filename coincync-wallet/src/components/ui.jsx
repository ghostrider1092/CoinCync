import { useContext, useState, useEffect, useCallback } from "react";
import { ThemeCtx } from "../App";

export const useTheme = () => useContext(ThemeCtx);

// ── Design Tokens ────────────────────────────────────────────────────
export const SP = { xs:2, sm:4, md:8, lg:12, xl:16, xxl:24, xxxl:32 };
export const RAD = { sm:6, md:8, lg:12, xl:14 };
export const SHADOW = {
  sm: (s) => `0 1px 3px ${s}`,
  md: (s) => `0 2px 8px ${s}`,
  lg: (s) => `0 8px 24px ${s}`,
  xl: (s) => `0 20px 60px ${s}`,
};
export const TIMING = { fast:".12s", normal:".2s", slow:".35s" };

// ── Icons ─────────────────────────────────────────────────────────────
export const Ico = ({ d, size=15, color="currentColor", fill="none" }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill={fill}
    stroke={color} strokeWidth={1.8} strokeLinecap="round" strokeLinejoin="round">
    <path d={d}/>
  </svg>
);

// ── Badge ─────────────────────────────────────────────────────────────
export const Badge = ({ label, color, variant="default" }) => {
  const [hovered, setHovered] = useState(false);
  const bg = variant === "solid" ? color : `${color}${hovered?"22":"14"}`;
  const textColor = variant === "solid" ? "#fff" : color;
  return (
    <span onMouseEnter={()=>setHovered(true)} onMouseLeave={()=>setHovered(false)}
      style={{ background:bg, color:textColor, border:`1px solid ${color}25`,
      borderRadius:20, padding:"2px 9px", fontSize:9, fontWeight:600,
      letterSpacing:.3, whiteSpace:"nowrap", display:"inline-flex", alignItems:"center", gap:3,
      transition:`background ${TIMING.fast} ease`, cursor:"default" }}>
      {label}
    </span>
  );
};

// ── Card ──────────────────────────────────────────────────────────────
export const Card = ({ children, style={}, hover=false, glow=false, onClick }) => {
  const T = useTheme();
  const [hovered, setHovered] = useState(false);
  return (
    <div onClick={onClick}
      onMouseEnter={()=>setHovered(true)}
      onMouseLeave={()=>setHovered(false)}
      style={{
        background:T.card, border:`1px solid ${hovered && (hover||onClick)?T.ac2+"40":T.b}`,
        borderRadius:RAD.xl, padding:`${SP.xxl-6}px ${SP.xxl-4}px`,
        boxShadow: glow && hovered
          ? `${SHADOW.lg(T.ac2+"15")}, ${SHADOW.md(T.shadow)}`
          : SHADOW.md(T.shadow),
        transition:`all ${TIMING.normal} ease`,
        cursor: onClick ? "pointer" : "default",
        ...style
      }}>
      {children}
    </div>
  );
};

// ── Label ─────────────────────────────────────────────────────────────
export const Lbl = ({ children }) => {
  const T = useTheme();
  return <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.8,
    textTransform:"uppercase", marginBottom:SP.md-2 }}>{children}</div>;
};

// ── Monospace text ────────────────────────────────────────────────────
export const Mono = ({ children, size=11, color }) => {
  const T = useTheme();
  return <span style={{ fontFamily:T.mono, fontSize:size, color:color||T.t2,
    wordBreak:"break-all", lineHeight:1.4 }}>{children}</span>;
};

// ── Divider ───────────────────────────────────────────────────────────
export const Divider = () => {
  const T = useTheme();
  return <div style={{ height:1, background:`linear-gradient(90deg, transparent, ${T.b}, transparent)`,
    margin:`${SP.xl}px 0` }}/>;
};

// ── Toggle ────────────────────────────────────────────────────────────
export const Toggle = ({ val, onToggle, disabled=false }) => {
  const T = useTheme();
  return (
    <div role="switch" aria-checked={val} tabIndex={disabled?-1:0}
      onClick={disabled?undefined:onToggle}
      onKeyDown={disabled?undefined:(e)=>{ if(e.key===" "||e.key==="Enter"){e.preventDefault();onToggle();} }}
      style={{ width:36, height:20, borderRadius:10,
        background:val?T.teal:`${T.b}`,
        border:`1px solid ${val?T.teal:T.b2}`,
        cursor:disabled?"not-allowed":"pointer", position:"relative",
        transition:`background ${TIMING.fast} ease, border ${TIMING.fast} ease`,
        opacity:disabled?.5:1, flexShrink:0 }}>
      <div style={{ width:14, height:14, borderRadius:"50%",
        background:"white", boxShadow:"0 1px 3px rgba(0,0,0,.2)",
        position:"absolute", top:2, left:val?19:2,
        transition:`left ${TIMING.fast} ease` }}/>
    </div>
  );
};

// ── Spinner ───────────────────────────────────────────────────────────
export const Spinner = ({ size=18, color }) => {
  const T = useTheme();
  return (
    <div style={{ width:size, height:size, border:`2px solid ${(color||T.ac2)}30`,
      borderTopColor:color||T.ac2, borderRadius:"50%",
      animation:"spin .7s linear infinite", flexShrink:0 }}/>
  );
};

// ── Skeleton ──────────────────────────────────────────────────────────
export const Skeleton = ({ width="100%", height=16, radius=RAD.sm, style={} }) => {
  const T = useTheme();
  return (
    <div style={{ width, height, borderRadius:radius,
      background:`linear-gradient(90deg, ${T.b} 25%, ${T.b2||T.b+"80"} 50%, ${T.b} 75%)`,
      backgroundSize:"200% 100%", animation:"shimmer 1.5s infinite", ...style }}/>
  );
};

// ── Modal ─────────────────────────────────────────────────────────────
export const Modal = ({ open, onClose, title, children, width=460 }) => {
  const T = useTheme();

  useEffect(() => {
    if (!open) return;
    const handler = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;
  return (
    <div role="dialog" aria-modal="true"
      onClick={(e)=>{ if(e.target===e.currentTarget) onClose(); }}
      style={{ position:"fixed", inset:0, background:"rgba(0,0,0,.65)",
        display:"flex", alignItems:"center", justifyContent:"center",
        zIndex:9999, animation:`fadeInFast ${TIMING.fast}` }}>
      <div style={{ background:T.card, border:`1px solid ${T.b}`, borderRadius:RAD.xl+2,
        maxWidth:width, width:"90%", padding:`${SP.xxl}px`,
        boxShadow:SHADOW.xl(T.shadow), animation:`slideUp ${TIMING.normal} ease` }}>
        {title && (
          <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center", marginBottom:SP.xl }}>
            <div style={{ fontSize:16, fontWeight:600 }}>{title}</div>
            <button onClick={onClose} style={{ background:`${T.b}80`, border:"none",
              borderRadius:RAD.md, width:28, height:28, cursor:"pointer",
              display:"flex", alignItems:"center", justifyContent:"center",
              transition:`background ${TIMING.fast}` }}
              onMouseEnter={e=>e.currentTarget.style.background=T.b}
              onMouseLeave={e=>e.currentTarget.style.background=`${T.b}80`}>
              <Ico d="M18 6L6 18M6 6l12 12" size={14} color={T.t3}/>
            </button>
          </div>
        )}
        {children}
      </div>
    </div>
  );
};

// ── Select ────────────────────────────────────────────────────────────
export const Select = ({ label, value, onChange, options, hint }) => {
  const T = useTheme();
  return (
    <div>
      {label && <Lbl>{label}</Lbl>}
      <select value={value} onChange={onChange}
        style={{ background:T.inputBg, border:`1.5px solid ${T.b}`, borderRadius:RAD.md,
          color:T.t1, padding:"8px 12px", fontSize:12, outline:"none", width:"100%",
          cursor:"pointer", transition:`border ${TIMING.normal} ease`,
          appearance:"none", backgroundImage:`url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 24 24' fill='none' stroke='%23888' stroke-width='2'%3E%3Cpath d='M6 9l6 6 6-6'/%3E%3C/svg%3E")`,
          backgroundRepeat:"no-repeat", backgroundPosition:"right 10px center", paddingRight:32 }}>
        {options.map(o => <option key={typeof o==="string"?o:o.value} value={typeof o==="string"?o:o.value}>
          {typeof o==="string"?o:o.label}
        </option>)}
      </select>
      {hint && <div style={{ fontSize:10, color:T.t3, marginTop:SP.sm }}>{hint}</div>}
    </div>
  );
};

// ── Section (reusable grouped card) ──────────────────────────────────
export const Section = ({ title, color, children }) => {
  const T = useTheme();
  return (
    <Card style={{ marginBottom:SP.lg-2 }}>
      <div style={{ fontSize:10, fontWeight:700, color:color||T.teal, letterSpacing:.8,
        textTransform:"uppercase", marginBottom:SP.lg-1 }}>{title}</div>
      {children}
    </Card>
  );
};

// ── Row (settings-style key/value row) ───────────────────────────────
export const Row = ({ label, locked, hint, children }) => {
  const T = useTheme();
  return (
    <div style={{ padding:`${SP.md+1}px 0`, borderBottom:`1px solid ${T.b}` }}>
      <div style={{ display:"flex", justifyContent:"space-between", alignItems:"center" }}>
        <span style={{ fontSize:12, color:locked?T.t3:T.t1 }}>
          {label}{locked&&<span style={{ fontSize:9, color:T.red, marginLeft:SP.md }}>locked by constitution</span>}
        </span>
        {children}
      </div>
      {hint && <div style={{ fontSize:9, color:T.t3, marginTop:3 }}>{hint}</div>}
    </div>
  );
};

// ── Empty State ──────────────────────────────────────────────────────
export const EmptyState = ({ icon, title, subtitle, action }) => {
  const T = useTheme();
  return (
    <div style={{ textAlign:"center", padding:`${SP.xxxl+8}px ${SP.xxl}px` }}>
      {icon && <div style={{ width:48, height:48, borderRadius:RAD.lg,
        background:`${T.ac2}10`, display:"flex", alignItems:"center", justifyContent:"center",
        margin:"0 auto", marginBottom:SP.xl }}>
        <Ico d={icon} size={22} color={T.ac2}/>
      </div>}
      <div style={{ fontSize:14, fontWeight:600, color:T.t2, marginBottom:SP.md-2 }}>{title}</div>
      {subtitle && <div style={{ fontSize:12, color:T.t3, lineHeight:1.5, maxWidth:320, margin:"0 auto" }}>{subtitle}</div>}
      {action && <div style={{ marginTop:SP.xl }}>{action}</div>}
    </div>
  );
};

// ── Button ────────────────────────────────────────────────────────────
export const Btn = ({ children, onClick, variant="primary", small=false, disabled=false, full=false, style={} }) => {
  const T = useTheme();
  const [pressed, setPressed] = useState(false);
  const [hovered, setHovered] = useState(false);
  const base = {
    display:"inline-flex", alignItems:"center", justifyContent:"center", gap:6,
    borderRadius:RAD.lg-2, fontWeight:600, border:"none",
    fontSize:small?11:13, letterSpacing:.2, width:full?"100%":"auto",
    cursor:disabled?"not-allowed":"pointer", opacity:disabled?.45:1,
    transition:`all ${TIMING.fast} ease`, position:"relative", overflow:"hidden",
    transform: pressed && !disabled ? "scale(0.97)" : hovered && !disabled ? "scale(1.01)" : "scale(1)",
    ...style
  };
  const vs = {
    primary:{ background:`linear-gradient(135deg, ${T.ac2}, ${T.ac})`, color:"#fff",
      padding:small?"6px 14px":"11px 22px",
      boxShadow: hovered && !disabled ? `0 4px 16px ${T.ac2}40` : `0 2px 12px ${T.ac2}30` },
    ghost:{ background: hovered && !disabled ? `${T.ac2}08` : "transparent", color:T.ac2,
      border:`1px solid ${hovered && !disabled ? T.ac2+"40" : T.b2}`,
      padding:small?"5px 13px":"10px 21px" },
    danger:{ background:`${T.red}${hovered && !disabled ? "1a" : "12"}`, color:T.red,
      border:`1px solid ${T.red}25`,
      padding:small?"5px 13px":"10px 21px" },
    dark:{ background: hovered && !disabled ? T.b2||T.b : T.b, color:T.t1,
      border:`1px solid ${T.b2}`,
      padding:small?"5px 13px":"10px 21px" },
  };
  return (
    <button
      onClick={disabled?undefined:onClick}
      onMouseDown={()=>setPressed(true)}
      onMouseUp={()=>setPressed(false)}
      onMouseEnter={()=>setHovered(true)}
      onMouseLeave={()=>{setPressed(false);setHovered(false);}}
      style={{...base,...(vs[variant]||vs.primary)}}>
      {children}
    </button>
  );
};

// ── Input ─────────────────────────────────────────────────────────────
export const Input = ({ label, value, onChange, placeholder, type="text", mono=false, hint, error, right, rows, disabled=false }) => {
  const T = useTheme();
  const [focused, setFocused] = useState(false);
  const borderColor = error ? T.red : focused ? T.ac2 : value ? `${T.ac2}50` : T.b;

  const inputStyle = {
    background:T.inputBg, border:`1.5px solid ${borderColor}`,
    borderRadius:RAD.lg-2, color:T.t1, fontFamily:mono?T.mono:"inherit",
    fontSize:13, padding:"10px 14px", width:"100%",
    outline:"none", paddingRight:right?"40px":"14px",
    transition:`border ${TIMING.normal} ease, box-shadow ${TIMING.normal} ease`,
    boxShadow: focused ? `0 0 0 3px ${T.ac2}12` : "none",
    resize: rows ? "vertical" : "none",
    opacity:disabled?.6:1, cursor:disabled?"not-allowed":"text",
  };

  return (
    <div>
      {label && <Lbl>{label}</Lbl>}
      <div style={{ position:"relative" }}>
        {rows
          ? <textarea value={value} onChange={onChange} placeholder={placeholder} rows={rows} disabled={disabled}
              onFocus={()=>setFocused(true)} onBlur={()=>setFocused(false)} style={inputStyle}/>
          : <input type={type} value={value} onChange={onChange} placeholder={placeholder} disabled={disabled}
              onFocus={()=>setFocused(true)} onBlur={()=>setFocused(false)} style={inputStyle}/>
        }
        {right && <div style={{ position:"absolute", right:12, top:"50%", transform:"translateY(-50%)" }}>{right}</div>}
      </div>
      {hint  && !error && <div style={{ fontSize:10, color:T.t3, marginTop:SP.sm, lineHeight:1.4 }}>{hint}</div>}
      {error && <div style={{ fontSize:10, color:T.red, marginTop:SP.sm, display:"flex", alignItems:"center", gap:4 }}>
        <Ico d={ICONS.warning} size={10} color={T.red}/>{error}
      </div>}
    </div>
  );
};

// ── Stat Card ─────────────────────────────────────────────────────────
export const StatCard = ({ label, value, sub, color, icon }) => {
  const T = useTheme();
  return (
    <Card hover>
      <div style={{ display:"flex", alignItems:"flex-start", justifyContent:"space-between" }}>
        <div>
          <div style={{ fontSize:10, fontWeight:600, color:T.t3, letterSpacing:.6,
            textTransform:"uppercase", marginBottom:SP.md-2 }}>{label}</div>
          <div style={{ fontFamily:T.serif, fontSize:26, fontWeight:400,
            color:color||T.t1, letterSpacing:-.5 }}>{value}</div>
          {sub && <div style={{ fontSize:10, color:T.t3, marginTop:3 }}>{sub}</div>}
        </div>
        {icon && <div style={{ width:36, height:36, borderRadius:RAD.lg-2,
          background:`${(color||T.ac2)}10`, display:"flex", alignItems:"center",
          justifyContent:"center" }}>
          <Ico d={icon} size={16} color={color||T.ac2}/>
        </div>}
      </div>
    </Card>
  );
};

// ── Coin Logo (SVG mark — Pedersen commitment ring) ──────────────────
export const CoinLogo = ({ size=64, style={} }) => {
  const T = useTheme();
  const accent = T.ac2 || "#d4a059";
  const bg = T.bg || "#0a0a09";
  return (
    <svg viewBox="0 0 200 200" width={size} height={size} style={{ display:"block", ...style }}>
      <circle cx="100" cy="100" r="78" fill="none" stroke={accent} strokeWidth="14"/>
      <path d="M 168 100 A 68 68 0 1 0 100 168" fill="none" stroke={bg} strokeWidth="22"/>
      <line x1="162" y1="100" x2="178" y2="100" stroke={bg} strokeWidth="22"/>
      <circle cx="68" cy="100" r="8" fill={accent}/>
      <circle cx="132" cy="100" r="8" fill={accent}/>
    </svg>
  );
};

// ── Icons ─────────────────────────────────────────────────────────────
export const ICONS = {
  dashboard:"M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2zM9 22V12h6v10",
  send:"M22 2L11 13M22 2L15 22 8 13 2 9z",
  receive:"M12 2v14M5 9l7 7 7-7",
  history:"M12 8v4l3 3M3.05 11a9 9 0 1 0 .5-4.5",
  addresses:"M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2M12 11a4 4 0 100-8 4 4 0 000 8z",
  mining:"M22 12h-4l-3 9L9 3l-3 9H2",
  keys:"M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4",
  constitution:"M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5",
  settings:"M12 15a3 3 0 100-6 3 3 0 000 6zM19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z",
  shield:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
  eye:"M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8zM12 9a3 3 0 100 6 3 3 0 000-6z",
  eyeOff:"M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24M1 1l22 22",
  copy:"M8 17.929H6c-1.105 0-2-.912-2-2.036V5.036C4 3.91 4.895 3 6 3h8c1.105 0 2 .911 2 2.036v1.866m-6 .17h8c1.105 0 2 .91 2 2.035v10.857C20 21.09 19.105 22 18 22h-8c-1.105 0-2-.911-2-2.036V9.107c0-1.124.895-2.036 2-2.036z",
  check:"M20 6L9 17l-5-5",
  lock:"M19 11H5a2 2 0 00-2 2v7a2 2 0 002 2h14a2 2 0 002-2v-7a2 2 0 00-2-2zM7 11V7a5 5 0 0110 0v4",
  unlock:"M11 11V7a4 4 0 018 0v1M5 11h14a2 2 0 012 2v7a2 2 0 01-2 2H5a2 2 0 01-2-2v-7a2 2 0 012-2z",
  close:"M18 6L6 18M6 6l12 12",
  refresh:"M23 4v6h-6M1 20v-6h6M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15",
  sun:"M12 1v2M12 21v2M4.22 4.22l1.42 1.42M18.36 18.36l1.42 1.42M1 12h2M21 12h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42M12 5a7 7 0 100 14A7 7 0 0012 5z",
  moon:"M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z",
  bell:"M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0",
  ledger:"M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5",
  privacy:"M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10zM9 12l2 2 4-4",
  warning:"M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0zM12 9v4M12 17h.01",
  info:"M12 22a10 10 0 100-20 10 10 0 000 20zM12 8h.01M11 12h1v4h1",
  arrowUp:"M12 19V5M5 12l7-7 7 7",
  arrowDown:"M12 5v14M5 12l7 7 7-7",
  fire:"M12 2c0 4-4 6-4 10a4 4 0 008 0c0-4-4-6-4-10z",
  globe:"M12 22a10 10 0 100-20 10 10 0 000 20zM2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10 15.3 15.3 0 014-10z",
  wallet:"M21 4H3a1 1 0 00-1 1v14a1 1 0 001 1h18a1 1 0 001-1V5a1 1 0 00-1-1zM16 14a2 2 0 110-4 2 2 0 010 4z",
};
