import { useEffect, useState } from "react";
import { CoinLogo } from "./ui";

// ── Modern minimalist splash — 2026-05-21 redesign ──────────────────
//
// Replaces the previous globe-with-nodes splash (which had a busy
// canvas animation + node status grid + bottom credits). New posture
// is Apple-style: less but more.
//
// Composition:
//   - Dark background with a subtle vignette + grain noise
//   - Single accent ring breathing behind the logo
//   - Large "CoinCync" wordmark (Fraunces) that fades in
//   - Brief tagline in mono below
//   - Thin progress line at the bottom that fills in real time
//
// Total run: 2400ms. The progress bar provides the only "loading"
// affordance — no spinners, no status text, no node counts.

const TOTAL_MS = 2400;
const FADE_OUT_MS = 500;

export default function SplashScreen({ onComplete }) {
  const [phase, setPhase] = useState(0);   // 0=initial, 1=logo, 2=text, 3=fading
  const [progress, setProgress] = useState(0);
  const [opacity, setOpacity] = useState(1);

  // Phase timing — fade-in choreography
  useEffect(() => {
    const t1 = setTimeout(() => setPhase(1), 200);    // Logo in
    const t2 = setTimeout(() => setPhase(2), 700);    // Wordmark + tagline in
    const t3 = setTimeout(() => setPhase(3), TOTAL_MS - FADE_OUT_MS); // Begin fade
    const t4 = setTimeout(() => setOpacity(0), TOTAL_MS - FADE_OUT_MS);
    const t5 = setTimeout(() => onComplete(), TOTAL_MS);
    return () => [t1, t2, t3, t4, t5].forEach(clearTimeout);
  }, [onComplete]);

  // Progress bar — fills smoothly across the full duration
  useEffect(() => {
    const start = Date.now();
    let raf;
    const tick = () => {
      const elapsed = Date.now() - start;
      const pct = Math.min(100, (elapsed / (TOTAL_MS - FADE_OUT_MS)) * 100);
      setProgress(pct);
      if (pct < 100) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  return (
    <div style={{
      position: "fixed", inset: 0, zIndex: 100000,
      background: "#0a0a0a",
      display: "flex", flexDirection: "column",
      alignItems: "center", justifyContent: "center",
      opacity, transition: `opacity ${FADE_OUT_MS}ms ease`,
      overflow: "hidden",
      // Subtle film grain for warmth — pure CSS, no asset needed.
      backgroundImage: `
        radial-gradient(ellipse 60% 50% at 50% 35%, rgba(212,160,89,0.06) 0%, transparent 60%),
        radial-gradient(ellipse 80% 80% at 50% 100%, rgba(34,214,140,0.04) 0%, transparent 50%)
      `,
    }}>
      {/* Breathing accent ring behind the logo */}
      <div style={{
        position: "absolute",
        width: 240, height: 240, borderRadius: "50%",
        marginBottom: 100,
        background: `radial-gradient(circle, rgba(212,160,89,0.12) 0%, transparent 65%)`,
        animation: "breathe 4s ease-in-out infinite",
        opacity: phase >= 1 ? 1 : 0,
        transition: "opacity 0.6s ease",
      }}/>

      {/* Logo */}
      <div style={{
        position: "relative", zIndex: 2,
        marginBottom: 36,
        opacity: phase >= 1 ? 1 : 0,
        transform: `scale(${phase >= 1 ? 1 : 0.85})`,
        transition: "opacity 0.7s cubic-bezier(.2,.7,.3,1), transform 0.7s cubic-bezier(.2,.7,.3,1)",
      }}>
        <CoinLogo size={80}/>
      </div>

      {/* Wordmark */}
      <div style={{
        position: "relative", zIndex: 2,
        opacity: phase >= 2 ? 1 : 0,
        transform: `translateY(${phase >= 2 ? 0 : 12}px)`,
        transition: "opacity 0.6s ease, transform 0.6s ease",
      }}>
        <div style={{
          fontFamily: "'Fraunces', Georgia, serif",
          fontSize: 44, fontWeight: 300,
          color: "#f5f0e8",
          letterSpacing: -1.5,
          textAlign: "center",
        }}>
          Coin<span style={{
            background: "linear-gradient(135deg, #e8c178 0%, #d4a059 100%)",
            WebkitBackgroundClip: "text", backgroundClip: "text",
            WebkitTextFillColor: "transparent", color: "transparent",
            fontWeight: 400,
          }}>Cync</span>
        </div>

        <div style={{
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 11, color: "rgba(245,240,232,0.45)",
          letterSpacing: "0.2em", textTransform: "uppercase",
          marginTop: 14, textAlign: "center",
        }}>
          Privacy that requires no permission
        </div>
      </div>

      {/* Progress line — fills 0 → 100% across the splash duration */}
      <div style={{
        position: "absolute", bottom: 60, left: "50%",
        transform: "translateX(-50%)",
        width: 200, height: 1,
        background: "rgba(245,240,232,0.08)",
        borderRadius: 1,
        opacity: phase >= 1 ? 1 : 0,
        transition: "opacity 0.4s ease",
        overflow: "hidden",
      }}>
        <div style={{
          height: "100%", width: `${progress}%`,
          background: "linear-gradient(90deg, transparent 0%, #d4a059 50%, transparent 100%)",
          backgroundSize: "200% 100%",
          animation: "shimmer 2s linear infinite",
          transition: "width 60ms linear",
        }}/>
      </div>

      {/* Version — minimal, bottom right */}
      <div style={{
        position: "absolute", bottom: 18, right: 22,
        fontFamily: "'JetBrains Mono', monospace",
        fontSize: 9, color: "rgba(245,240,232,0.2)",
        letterSpacing: "0.1em",
        opacity: phase >= 2 ? 1 : 0,
        transition: "opacity 0.8s ease",
      }}>
        v1.0.8 · testnet
      </div>
    </div>
  );
}
