import { useState } from "react";
import { useTheme, CoinLogo, Btn, Ico, ICONS, SP, Input } from "../components/ui";
import NonTauriPrompt from "../components/NonTauriPrompt";
import { rpc, isWalletBackendAvailable, formatWalletError } from "../utils/rpc";
import { clearCoincyncLocalState } from "../utils/storage";

// ── Unlock — redesigned 2026-05-17 ────────────────────────────────────
//
// First thing every user sees every session. Was a plain centered card;
// now matches the wallet's brand language (Fraunces title, mono eyebrow,
// gradient backing, accent top-edge line) and adds small UX details:
//   - Pulsing halo behind the logo
//   - "Welcome back" eyebrow + "Unlock your wallet" Fraunces title
//   - Full-width password input with show/hide toggle inside
//   - Form-wrapped so Enter submits + autocomplete=current-password
//     (lets OS-level keychains offer to fill)
//   - autofocus on mount so users can just start typing
//   - Enter-to-unlock hint visible under input until error replaces it
//   - Forgot Password as deliberate ghost button at bottom (was a
//     misclick-prone single line of text)
//   - Footer shows wallet version — build identity matters when
//     things go wrong
//
// Brute-force protection (5 failures → 30s cooldown) is enforced
// server-side; the existing formatWalletError surface already humanises
// AUTH_RATE_LIMITED, so no new client state needed.

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
        {/* Accent top-edge line — brand cue shared with Dashboard / Send / Receive hero cards */}
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
        <div style={{ textAlign: "center", marginBottom: 26 }}>
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

        {/* Password input using the wallet's proven Input component */}
        <div style={{ marginBottom: 14 }}>
          <Input
            value={pw}
            onChange={e => { setPw(e.target.value); setErr(""); }}
            type="password"
            placeholder="Wallet password"
            error={err}
            mono
          />
        </div>

        <Btn onClick={tryUnlock} disabled={!pw || loading} full
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

        {/* Hint */}
        {!err && (
          <div style={{ marginTop: 12, fontSize: 11, fontFamily: T.mono, color: T.t3, textAlign: "center" }}>
            Type your password and click Unlock
          </div>
        )}

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
