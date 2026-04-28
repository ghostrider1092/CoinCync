import { useState } from "react";
import { useTheme, CoinLogo, Ico, ICONS } from "./ui";

const SLIDES = [
  {
    title: "Welcome to CoinCync",
    sub: "The private cryptocurrency",
    body: "CoinCync is a privacy-first cryptocurrency. Every transaction is automatically private — your identity, your amounts, and your activity are cryptographically hidden from everyone.",
    icon: "M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z",
    color: "#d4a059",
  },
  {
    title: "Your Seed Phrase",
    sub: "Write it down. Keep it safe.",
    body: "When you create a wallet, you'll receive a 24-word seed phrase. This is the ONLY way to recover your wallet. If you lose it, your coins are gone forever. Never share it with anyone. Never type it into a website.",
    icon: "M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3",
    color: "#F0C040",
  },
  {
    title: "Mine CYNC",
    sub: "One click. Your CPU. Real coins.",
    body: "CoinCync uses RandomX — a CPU-only mining algorithm. No expensive GPUs needed. Go to the Mining tab, enter your address, and click Start. Your computer earns ~50 CYNC per block found.",
    icon: "M22 12h-4l-3 9L9 3l-3 9H2",
    color: "#d4a059",
  },
  {
    title: "22 Privacy Features",
    sub: "Private by law. Private by math.",
    body: "Ring signatures hide the sender. Stealth addresses hide the receiver. Bulletproofs+ hide the amount. Dandelion++ hides your IP. No one — not even us — can see your transactions. This is enforced by the Constitution at Block 0.",
    icon: "M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z",
    color: "#d4a059",
  },
];

export default function Onboarding({ onComplete }) {
  const T = useTheme();
  const [slide, setSlide] = useState(0);
  const s = SLIDES[slide];
  const isLast = slide === SLIDES.length - 1;

  return (
    <div style={{ height:"100vh", display:"flex", flexDirection:"column",
      alignItems:"center", justifyContent:"center", background:T.bg, padding:40 }}>

      {/* Logo */}
      <CoinLogo size={60}/>

      {/* Slide */}
      <div key={slide} style={{ textAlign:"center", maxWidth:480, marginTop:32, animation:"fadeIn .3s ease" }}>
        <div style={{ width:64, height:64, borderRadius:16, background:`${s.color}15`,
          display:"flex", alignItems:"center", justifyContent:"center", margin:"0 auto 20px" }}>
          <Ico d={s.icon} size={28} color={s.color}/>
        </div>
        <h1 style={{ fontFamily:T.serif, fontSize:26, fontWeight:400, marginBottom:6 }}>{s.title}</h1>
        <p style={{ fontFamily:T.serif, fontStyle:"italic", fontSize:13, color:T.ac2, marginBottom:16 }}>{s.sub}</p>
        <p style={{ fontSize:13, color:T.t2, lineHeight:1.8 }}>{s.body}</p>
      </div>

      {/* Dots */}
      <div style={{ display:"flex", gap:8, marginTop:32 }}>
        {SLIDES.map((_, i) => (
          <div key={i} onClick={()=>setSlide(i)} style={{
            width: i===slide ? 24 : 8, height:8, borderRadius:4,
            background: i===slide ? T.ac2 : T.b2,
            cursor:"pointer", transition:"all .2s"
          }}/>
        ))}
      </div>

      {/* Buttons */}
      <div style={{ display:"flex", gap:12, marginTop:28 }}>
        {slide > 0 && (
          <button onClick={()=>setSlide(s=>s-1)} style={{
            background:"none", border:`1px solid ${T.b2}`, borderRadius:10,
            padding:"10px 24px", color:T.t2, fontSize:13, fontWeight:600, cursor:"pointer"
          }}>Back</button>
        )}
        <button onClick={()=> isLast ? onComplete() : setSlide(s=>s+1)} style={{
          background:`linear-gradient(135deg, ${T.ac2}, ${T.ac})`, border:"none",
          borderRadius:10, padding:"10px 32px", color:"#fff", fontSize:13, fontWeight:700,
          cursor:"pointer", boxShadow:`0 2px 12px ${T.ac2}30`
        }}>
          {isLast ? "Get Started" : "Next"}
        </button>
      </div>

      {/* Skip */}
      {!isLast && (
        <button onClick={onComplete} style={{
          background:"none", border:"none", color:T.t3, fontSize:11,
          marginTop:16, cursor:"pointer"
        }}>Skip tutorial</button>
      )}
    </div>
  );
}
