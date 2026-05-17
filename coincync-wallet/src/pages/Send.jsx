import { useState, useEffect, useContext, useRef } from "react";
import { useTheme, Card, Badge, Btn, Lbl, Input, Ico, CoinLogo, ICONS, SP } from "../components/ui";
import { rpc } from "../utils/rpc";
import { WalletCtx, NotifCtx, NavCtx } from "../appContexts";

// ── Send — redesigned 2026-05-17 ──────────────────────────────────────
//
// Hierarchy (top to bottom = primary action to detail):
//   1. Amount hero — big numeric input, balance reference, MAX button
//      prominent. The PRIMARY thing happening on this page.
//   2. Recipient card — paste-friendly, inline validation, smart
//      address-type display.
//   3. Options strip — fee priority + memo. Both inline, no expander
//      gymnastics; users who care can scan and pick.
//   4. Summary + Send button — one-line fee+total, single big Send.
//   5. Privacy callout — collapsed by default; expander reveals the
//      6-feature grid for users who want the educational moment.
//
// Kept from the prior design: the scramble-on-confirm button animation
// (brand character, lines up with the actual signing delay) and the
// confirmation modal (correct safety UX for irreversible action).
//
// Redesigned: success state down from 5 badges to 3 + clear next-actions
// (Send Another / Back to Dashboard). Fee breakdown collapsed from a
// 3-line panel to a single inline summary.

// Encrypt-style text scramble — see useScrambledText comment in old file.
const SCRAMBLE_CHARS = "!@#$%^&*():{};|,.<>/?";
function useScrambledText(target, active, durationMs = 600) {
  const [text, setText] = useState(target);
  const intRef = useRef(null);
  useEffect(() => {
    if (intRef.current) { clearInterval(intRef.current); intRef.current = null; }
    if (!active) { setText(target); return; }
    const interval = 50;
    const cyclesPerChar = 2;
    let pos = 0;
    intRef.current = setInterval(() => {
      const out = target.split("").map((c, i) => {
        if (pos / cyclesPerChar > i) return c;
        return SCRAMBLE_CHARS[Math.floor(Math.random() * SCRAMBLE_CHARS.length)];
      }).join("");
      setText(out);
      pos++;
      if (pos >= target.length * cyclesPerChar) {
        clearInterval(intRef.current); intRef.current = null;
        setText(target);
      }
    }, interval);
    return () => {
      if (intRef.current) { clearInterval(intRef.current); intRef.current = null; }
    };
  }, [active, target, durationMs]);
  return text;
}

const PRIVACY_LAYERS_APPLIED = [
  ["CLSAG Ring-11", "11 decoys from entire UTXO set", "ac2"],
  ["Uniform 2-in/2-out", "Fixed transaction shape", "amber"],
  ["Pedersen Commits", "Amounts cryptographically hidden", "ac2"],
  ["Bulletproofs+", "Range proof on every output", "ac2"],
  ["Dandelion++", "IP-hiding propagation path", "blue"],
  ["Traffic Shaping", "0-200ms jitter + size norm + cover packets", "amber"],
];

export default function Send() {
  const T = useTheme();
  const { balance, fees } = useContext(WalletCtx);
  const { push } = useContext(NotifCtx);
  const { navigateTo } = useContext(NavCtx);

  const [addr, setAddr]         = useState("");
  const [amount, setAmount]     = useState("");
  const [memo, setMemo]         = useState("");
  const [priority, setPriority] = useState("normal");
  const [addrValid, setAddrValid] = useState(null);
  const [sending, setSending]   = useState(false);
  const [done, setDone]         = useState(false);
  const [txid, setTxid]         = useState("");
  const [confirming, setConfirming] = useState(false);
  const [scrambling, setScrambling] = useState(false);
  const [showPrivacyDetail, setShowPrivacyDetail] = useState(false);

  // Debounced address validation
  useEffect(() => {
    if (!addr || addr.length < 5) { setAddrValid(null); return; }
    const t = setTimeout(async () => {
      try {
        const r = await rpc.validateAddress(addr);
        setAddrValid(r);
      } catch {
        setAddrValid({ valid: false, type: "unavailable" });
      }
    }, 400);
    return () => clearTimeout(t);
  }, [addr]);

  const confirmText = useScrambledText("Confirm Send", scrambling, 600);

  function handleConfirmClick() {
    if (scrambling || sending) return;
    setScrambling(true);
    setTimeout(() => {
      setScrambling(false);
      confirmSend();
    }, 600);
  }

  const feeMap = { slow: fees.slow, normal: fees.normal, fast: fees.fast, flash: fees.flash };
  const fee = feeMap[priority] || "0.000005984000";
  const amountNum = parseFloat(amount) || 0;
  const feeNum = parseFloat(fee) || 0;
  const totalNum = amountNum + feeNum;
  const total = amount && amountNum > 0 ? totalNum.toFixed(6) : "—";
  const balanceNum = parseFloat(balance.unlocked) || 0;
  const amountError = amountNum > balanceNum ? "Exceeds balance" : amountNum < 0 ? "Must be positive" : "";

  function sendMax() {
    const max = Math.max(0, balanceNum - feeNum);
    setAmount(max > 0 ? max.toFixed(6) : "0");
  }

  async function pasteAddr() {
    try {
      const t = await navigator.clipboard.readText();
      if (t) setAddr(t.trim());
    } catch {
      push("Clipboard read denied — paste manually with Ctrl+V", "warning");
    }
  }

  function trySend() {
    if (!addr || !amount || !addrValid?.valid || amountNum <= 0 || amountError) return;
    setConfirming(true);
  }

  async function confirmSend() {
    setConfirming(false);
    setSending(true);
    try {
      const r = await rpc.sendTransaction({ to: addr, amount, memo, priority });
      setTxid(r.txid); setDone(true);
      push(`Sent! Tx: ${r.txid.slice(0, 16)}…`, "success");
    } catch(e) { push("Send failed: " + e, "error"); }
    setSending(false);
  }

  // ── Success state ────────────────────────────────────────────────
  if (done) return <SuccessState txid={txid} T={T}
    onSendAnother={() => { setDone(false); setAddr(""); setAmount(""); setMemo(""); setTxid(""); }}
    onBackToDash={() => navigateTo("dashboard")}/>;

  // ── Main form ────────────────────────────────────────────────────
  return (
    <div style={{ animation: "fadeIn .25s ease", maxWidth: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: SP.lg }}>
        <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t3, letterSpacing: ".14em", textTransform: "uppercase" }}>
          Send CYNC
        </div>
        <h1 style={{ fontFamily: T.serif, fontSize: 22, fontWeight: 400, marginTop: 2 }}>
          Where to?
        </h1>
      </div>

      {/* ═══ Amount hero ═══ */}
      <Card style={{
        marginBottom: SP.lg,
        padding: "22px 26px 18px",
        background: `linear-gradient(135deg, ${T.card} 0%, ${T.ac2}08 60%, ${T.card} 100%)`,
        border: `1px solid ${T.ac2}28`,
        position: "relative", overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 2,
          background: `linear-gradient(90deg, transparent, ${T.ac2}, transparent)`,
          opacity: 0.6,
        }}/>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 10 }}>
          <div style={{ fontSize: 10, fontWeight: 600, color: T.t3, letterSpacing: ".12em", textTransform: "uppercase" }}>
            Amount
          </div>
          <button onClick={sendMax} style={{
            background: T.acb, border: `1px solid ${T.ac2}30`, borderRadius: 999,
            padding: "3px 10px", fontSize: 9, fontWeight: 700, color: T.ac2,
            cursor: "pointer", fontFamily: T.mono, letterSpacing: ".05em",
          }}>
            MAX
          </button>
        </div>
        <input value={amount}
          onChange={e => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
          placeholder="0.000000"
          style={{
            width: "100%", padding: "4px 0", border: "none", outline: "none",
            background: "transparent",
            fontFamily: T.mono, fontSize: 38, fontWeight: 600,
            color: amountNum > 0 ? T.ac2 : T.t3,
            letterSpacing: -.5,
          }}/>
        <div style={{ marginTop: 6, display: "flex", justifyContent: "space-between", alignItems: "center", fontSize: 11, color: T.t3 }}>
          <span style={{ fontFamily: T.mono }}>
            Available: <span style={{ color: T.t2 }}>{balance.unlocked || "—"} CYNC</span>
          </span>
          {amountError && (
            <span style={{ color: T.red, fontSize: 11, display: "inline-flex", alignItems: "center", gap: 4 }}>
              <Ico d={ICONS.warning} size={11} color={T.red}/>
              {amountError}
            </span>
          )}
        </div>
      </Card>

      {/* ═══ Recipient ═══ */}
      <Card style={{ marginBottom: SP.lg, padding: "14px 18px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
          <Lbl>Recipient address</Lbl>
          <button onClick={pasteAddr} style={{
            background: "none", border: "none", color: T.ac2,
            fontSize: 10, fontWeight: 600, cursor: "pointer",
            display: "inline-flex", alignItems: "center", gap: 4,
            fontFamily: T.mono,
          }}>
            <Ico d={ICONS.copy} size={11} color={T.ac2}/>
            Paste
          </button>
        </div>
        <input value={addr}
          onChange={e => setAddr(e.target.value)}
          placeholder="tCYNC3... stealth address"
          style={{
            width: "100%", padding: "10px 12px", borderRadius: 8,
            background: T.bg, color: T.t1, outline: "none",
            border: `1px solid ${
              addrValid === null ? T.b :
              addrValid.valid ? `${T.green}50` : `${T.red}50`
            }`,
            fontFamily: T.mono, fontSize: 12,
            transition: "border-color .15s",
          }}/>
        <div style={{ marginTop: 6, fontSize: 10, fontFamily: T.mono, minHeight: 14 }}>
          {addrValid === null && addr && addr.length >= 5 && (
            <span style={{ color: T.t3 }}>checking…</span>
          )}
          {addrValid?.valid && (
            <span style={{ color: T.green, display: "inline-flex", alignItems: "center", gap: 5 }}>
              <Ico d={ICONS.check} size={11} color={T.green}/>
              {addrValid.type} address · one-time stealth generated automatically
            </span>
          )}
          {addrValid && !addrValid.valid && (
            <span style={{ color: T.red, display: "inline-flex", alignItems: "center", gap: 5 }}>
              <Ico d={ICONS.warning} size={11} color={T.red}/>
              Invalid — must start with tCYNC or CYNC
            </span>
          )}
        </div>
      </Card>

      {/* ═══ Options strip — fee + memo ═══ */}
      <Card style={{ marginBottom: SP.lg, padding: "14px 18px" }}>
        <div style={{ marginBottom: 14 }}>
          <Lbl>Fee priority</Lbl>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(4, 1fr)", gap: 6, marginTop: 6 }}>
            {[["slow", "~10m"], ["normal", "~5m"], ["fast", "~2m"], ["flash", "~1m"]].map(([p, t]) => (
              <button key={p} onClick={() => setPriority(p)} style={{
                padding: "8px 6px", borderRadius: 8, cursor: "pointer",
                border: `1px solid ${priority === p ? T.ac2 : T.b}`,
                background: priority === p ? T.acb : T.bg,
                transition: "all .15s",
              }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: priority === p ? T.ac2 : T.t2, textTransform: "capitalize" }}>{p}</div>
                <div style={{ fontSize: 9, color: T.t3, marginTop: 1 }}>{t}</div>
                <div style={{ fontSize: 8, fontFamily: T.mono, color: T.t3, marginTop: 2 }}>{feeMap[p] || "…"} CYNC</div>
              </button>
            ))}
          </div>
        </div>

        <div>
          <Lbl>Encrypted memo <span style={{ color: T.t3, fontWeight: 400, fontSize: 10 }}>(optional · ChaCha20+ECDH · only recipient can read)</span></Lbl>
          <input value={memo}
            onChange={e => setMemo(e.target.value)}
            placeholder="Optional note — encrypted to recipient's view key"
            maxLength={256}
            style={{
              width: "100%", padding: "10px 12px", borderRadius: 8,
              background: T.bg, color: T.t1, outline: "none",
              border: `1px solid ${T.b}`,
              fontSize: 11, marginTop: 6,
            }}/>
        </div>
      </Card>

      {/* ═══ Summary + Send button ═══ */}
      <Card style={{ marginBottom: SP.md, padding: "16px 20px" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, fontSize: 11, color: T.t3 }}>
          <span>Network fee · {priority} · burn 30% of fee</span>
          <span style={{ fontFamily: T.mono }}>{fee} CYNC</span>
        </div>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 14, paddingBottom: 12, borderBottom: `1px solid ${T.b}` }}>
          <span style={{ fontSize: 12, fontWeight: 600 }}>Total</span>
          <span style={{ fontFamily: T.mono, fontSize: 16, fontWeight: 600, color: amountNum > 0 ? T.ac2 : T.t3 }}>{total} CYNC</span>
        </div>
        <Btn onClick={trySend}
          disabled={!addr || !amount || amountNum <= 0 || !addrValid?.valid || sending || !!amountError}
          full
          style={{ padding: 13, fontSize: 13 }}>
          {sending
            ? <div style={{ width: 16, height: 16, border: "2px solid #fff", borderTopColor: "transparent", borderRadius: "50%", animation: "spin .7s linear infinite" }}/>
            : <Ico d={ICONS.send} size={14} color="#fff"/>}
          {sending ? "Sending…" : "Send CYNC"}
        </Btn>
      </Card>

      {/* ═══ Privacy detail (collapsible) ═══ */}
      <button onClick={() => setShowPrivacyDetail(!showPrivacyDetail)} style={{
        background: "none", border: "none", color: T.t3,
        fontSize: 10, fontWeight: 600, cursor: "pointer",
        fontFamily: T.mono, letterSpacing: ".1em", textTransform: "uppercase",
        display: "flex", alignItems: "center", gap: 6, padding: "8px 0",
        width: "100%", justifyContent: "center",
      }}>
        {showPrivacyDetail ? "Hide" : "What's enforced on this transaction"}
        <span style={{ fontSize: 9 }}>{showPrivacyDetail ? "▾" : "▸"}</span>
      </button>
      {showPrivacyDetail && (
        <Card style={{ padding: "12px 16px", animation: "fadeIn .15s ease" }}>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 6 }}>
            {PRIVACY_LAYERS_APPLIED.map(([title, desc, colorKey]) => {
              const c = T[colorKey] || T.ac2;
              return (
                <div key={title} style={{
                  background: `${c}09`, border: `1px solid ${c}20`, borderRadius: 7,
                  padding: "8px 10px",
                }}>
                  <div style={{ fontSize: 10, fontWeight: 600, color: c }}>{title}</div>
                  <div style={{ fontSize: 9, color: T.t3, marginTop: 2 }}>{desc}</div>
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* ═══ Confirmation modal ═══ */}
      {confirming && (
        <ConfirmModal
          T={T} addr={addr} amount={amountNum} fee={fee} total={total} memo={memo}
          confirmText={confirmText}
          disabled={scrambling || sending}
          onConfirm={handleConfirmClick}
          onCancel={() => setConfirming(false)}
        />
      )}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────

function ConfirmModal({ T, addr, amount, fee, total, memo, confirmText, disabled, onConfirm, onCancel }) {
  return (
    <div style={{
      position: "fixed", inset: 0, background: "rgba(0,0,0,0.7)",
      display: "flex", alignItems: "center", justifyContent: "center",
      zIndex: 9999, animation: "fadeInFast .15s",
    }}>
      <Card style={{ maxWidth: 440, width: "92%", padding: "26px 26px 22px", position: "relative" }}>
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 2,
          background: `linear-gradient(90deg, transparent, ${T.ac2}, transparent)`,
          opacity: 0.6,
        }}/>
        <div style={{ textAlign: "center", marginBottom: 18 }}>
          <div style={{ fontFamily: T.serif, fontSize: 20, fontWeight: 400, marginBottom: 4 }}>Confirm Send</div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t3, letterSpacing: ".1em", textTransform: "uppercase" }}>
            This action cannot be undone
          </div>
        </div>
        <div style={{ background: T.bg, borderRadius: 10, padding: "14px 16px", marginBottom: 14, border: `1px solid ${T.b}` }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 10 }}>
            <span style={{ color: T.t3 }}>To</span>
            <span style={{ fontFamily: T.mono, fontSize: 10, color: T.t2 }}>
              {addr.slice(0, 18)}…{addr.slice(-10)}
            </span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 10 }}>
            <span style={{ color: T.t3 }}>Amount</span>
            <span style={{ fontFamily: T.mono, fontWeight: 600, color: T.ac2, fontSize: 13 }}>
              {amount.toFixed(6)} CYNC
            </span>
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 10 }}>
            <span style={{ color: T.t3 }}>Fee</span>
            <span style={{ fontFamily: T.mono, fontSize: 10, color: T.t2 }}>{fee} CYNC</span>
          </div>
          {memo && (
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: 11, marginBottom: 10 }}>
              <span style={{ color: T.t3 }}>Memo</span>
              <span style={{ fontSize: 10, color: T.t2, fontStyle: "italic", maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                "{memo}"
              </span>
            </div>
          )}
          <div style={{
            display: "flex", justifyContent: "space-between",
            fontSize: 13, fontWeight: 700,
            borderTop: `1px solid ${T.b}`, paddingTop: 10,
          }}>
            <span>Total</span>
            <span style={{ fontFamily: T.mono }}>{total} CYNC</span>
          </div>
        </div>
        <div style={{ display: "flex", gap: 8 }}>
          <Btn variant="ghost" full onClick={onCancel}>Cancel</Btn>
          <Btn full onClick={onConfirm} disabled={disabled}>{confirmText}</Btn>
        </div>
      </Card>
    </div>
  );
}

function SuccessState({ txid, T, onSendAnother, onBackToDash }) {
  const [copied, setCopied] = useState(false);
  function copyTxid() {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(txid).then(() => {
        setCopied(true); setTimeout(() => setCopied(false), 1500);
      });
    }
  }
  return (
    <div style={{
      display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
      minHeight: 460, animation: "fadeIn .3s ease", gap: 18,
    }}>
      <div style={{
        position: "relative",
        animation: "fadeIn .5s ease",
      }}>
        <div style={{
          position: "absolute", inset: -14, borderRadius: "50%",
          background: `radial-gradient(circle, ${T.ac2}20 0%, transparent 70%)`,
          animation: "pulse 2s ease-in-out infinite",
        }}/>
        <CoinLogo size={72}/>
      </div>
      <div style={{ textAlign: "center" }}>
        <div style={{ fontFamily: T.serif, fontSize: 24, fontWeight: 400 }}>
          Transaction sent
        </div>
        <div style={{ fontSize: 11, color: T.t3, marginTop: 4, fontFamily: T.mono, letterSpacing: ".08em", textTransform: "uppercase" }}>
          private by law · private by math
        </div>
      </div>
      <div style={{
        display: "flex", alignItems: "center", gap: 8,
        background: T.acb, border: `1px solid ${T.ac2}30`,
        borderRadius: 8, padding: "8px 14px",
        cursor: "pointer",
      }} onClick={copyTxid}>
        <span style={{ fontFamily: T.mono, fontSize: 11, color: T.t2 }}>
          {txid.slice(0, 16)}…{txid.slice(-8)}
        </span>
        <Ico d={ICONS.copy} size={11} color={T.ac2}/>
        {copied && (
          <span style={{ fontSize: 10, color: T.green, fontWeight: 600 }}>copied</span>
        )}
      </div>
      <div style={{ display: "flex", gap: 8, flexWrap: "wrap", justifyContent: "center", maxWidth: 380 }}>
        <Badge label="CLSAG signed" color={T.ac2}/>
        <Badge label="Pedersen committed" color={T.ac2}/>
        <Badge label="Dandelion++ routed" color={T.blue}/>
      </div>
      <div style={{ display: "flex", gap: 10, marginTop: 8 }}>
        <Btn variant="ghost" onClick={onBackToDash}>Back to Dashboard</Btn>
        <Btn onClick={onSendAnother}>Send Another</Btn>
      </div>
    </div>
  );
}
