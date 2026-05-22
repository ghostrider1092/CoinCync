import { useState } from "react";
import { useTheme, CoinLogo, Btn, Ico, ICONS, SP, Input } from "../components/ui";
import NonTauriPrompt from "../components/NonTauriPrompt";
import { rpc, isWalletBackendAvailable, formatWalletError } from "../utils/rpc";
import { clearCoincyncLocalState } from "../utils/storage";

// ── Unlock — redesigned 2026-05-17, hardened 2026-05-21 ──────────────
//
// First thing every user sees every session. Visual: Fraunces title,
// mono eyebrow, gradient backing, accent top-edge line, pulsing halo
// behind the logo, footer with version + forgot-password.
//
// Hardened 2026-05-21 after a "can't type in password / freezes" bug:
//   - Uses the wallet's proven <Input> component (NOT a raw <input>).
//     The raw input + show/hide toggle overlay had a subtle issue in
//     Tauri's webview that masked keystrokes.
//   - Btn passed `type="submit"` (Btn now propagates `type` properly,
//     fix in components/ui.jsx). No onClick on the Btn — the form's
//     onSubmit handles unlocking once.  Eliminates the double-call
//     race that the previous "type=submit + onClick" pattern caused.
//   - App.jsx's auto-lock listener no longer re-renders the entire
//     App tree on every keystroke (was using state, now uses ref).
//     That was the load-bearing fix that made typing feel responsive
//     in the heavy gradient/halo/animation context.
//
// Brute-force protection (5 failures → 30s cooldown) enforced
// server-side; formatWalletError humanises AUTH_RATE_LIMITED.

export default function Unlock({ onUnlock }) {
  const T = useTheme();
  const [pw, setPw]   = useState("");
  const [err, setErr] = useState("");
  const [loading, setLoading] = useState(false);

  async function tryUnlock() {
    if (!pw) { setErr("Enter your password"); return; }
    setLoading(true);
    setErr("");
    try {
      const result = await rpc.unlockWallet(pw);
      if (result) { onUnlock(); }
      else { setErr("Incorrect password"); }
    } catch (e) {
      setErr(formatWalletError(e, "Unlock failed"));
    }
    setLoading(false);
  }

  function onForgot() {
    const ok = window.confirm(
      "Password recovery will reset this app's local CoinCync state " +
      "and return to wallet setup.\n\n" +
      "You'll need your 24-word seed phrase to restore — without it, " +
      "the wallet file becomes unrecoverable.\n\n" +
      "Continue?"
    );
    if (!ok) return;
    clearCoincyncLocalState();
    window.location.reload();
  }

  if (!isWalletBackendAvailable()) {
    return <NonTauriPrompt />;
  }

  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "center",
      minHeight: "100vh", background: T.bg, padding: SP.lg,
    }}>
      <div style={{
        position: "relative", width: 420, maxWidth: "100%",
        background: `linear-gradient(135deg, ${T.card} 0%, ${T.ac2}06 60%, ${T.card} 100%)`,
        border: `1px solid ${T.ac2}28`,
        borderRadius: 16,
        padding: "44px 38px 28px",
        boxShadow: `0 20px 60px ${T.shadow}`,
        overflow: "hidden",
      }}>
        {/* Accent top-edge line */}
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 2,
          background: `linear-gradient(90deg, transparent, ${T.ac2}, transparent)`,
          opacity: 0.7,
        }}/>

        {/* Logo with pulsing halo */}
        <div style={{
          display: "flex", justifyContent: "center", alignItems: "center",
          marginBottom: 22, position: "relative", height: 88,
        }}>
          <div style={{
            position: "absolute", width: 100, height: 100, borderRadius: "50%",
            background: `radial-gradient(circle, ${T.ac2}25 0%, transparent 70%)`,
            animation: "pulse 3s ease-in-out infinite",
          }}/>
          <div style={{ position: "relative" }}>
            <CoinLogo size={72}/>
          </div>
        </div>

        {/* Title */}
        <div style={{ textAlign: "center", marginBottom: 22 }}>
          <div style={{
            fontFamily: T.mono, fontSize: 10, color: T.t3,
            letterSpacing: ".16em", textTransform: "uppercase", marginBottom: 4,
          }}>
            Welcome back
          </div>
          <h2 style={{
            fontFamily: T.serif, fontSize: 24, fontWeight: 400,
            color: T.t1, letterSpacing: -.01,
          }}>
            Unlock your wallet
          </h2>
        </div>

        {/* Password form — Enter submits; Btn type="submit" so click
            also submits (one path through onSubmit). No onClick on Btn
            to avoid the double-call bug. */}
        <form onSubmit={e => { e.preventDefault(); tryUnlock(); }}>
          <Input
            value={pw}
            onChange={e => { setPw(e.target.value); setErr(""); }}
            type="password"
            placeholder="Wallet password"
            error={err}
            mono
          />

          {/* Enter-to-unlock hint, replaced by error if any */}
          <div style={{
            minHeight: 18, marginTop: 6, marginBottom: 12,
            fontSize: 11, fontFamily: T.mono,
            color: err ? T.red : T.t3,
            textAlign: "left",
          }}>
            {err
              ? err
              : <>Press <kbd style={{
                  fontFamily: T.mono, fontSize: 10,
                  background: T.bg, border: `1px solid ${T.b}`, borderRadius: 4,
                  padding: "1px 6px", color: T.t2,
                }}>Enter</kbd> to unlock</>}
          </div>

          <Btn type="submit" disabled={!pw || loading} full
            style={{ padding: "13px 0", fontSize: 13, fontWeight: 700 }}>
            {loading ? (
              <div style={{
                width: 16, height: 16,
                border: "2px solid currentColor", borderTopColor: "transparent",
                borderRadius: "50%", animation: "spin .7s linear infinite",
              }}/>
            ) : (
              <Ico d={ICONS.lock} size={14} color="currentColor"/>
            )}
            {loading ? "Unlocking…" : "Unlock"}
          </Btn>
        </form>

        {/* Footer: version + forgot password */}
        <div style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          marginTop: 22, paddingTop: 14, borderTop: `1px solid ${T.b}`,
        }}>
          <div style={{
            fontSize: 9, fontFamily: T.mono, color: T.t3,
            letterSpacing: ".06em",
          }}>
            CoinCync · v1.0.8
          </div>
          <button onClick={onForgot} style={{
            background: "none", border: "none", color: T.t3,
            fontSize: 10, fontFamily: T.mono, cursor: "pointer",
            padding: "4px 8px", borderRadius: 6,
            transition: "color .12s, background .12s",
          }}
            onMouseEnter={e => { e.currentTarget.style.color = T.amber; e.currentTarget.style.background = `${T.amber}10`; }}
            onMouseLeave={e => { e.currentTarget.style.color = T.t3; e.currentTarget.style.background = "transparent"; }}>
            Forgot password? <span style={{ color: T.t3 }}>(needs seed)</span>
          </button>
        </div>
      </div>
    </div>
  );
}
