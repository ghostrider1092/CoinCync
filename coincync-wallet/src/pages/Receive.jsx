import React, { useState, useEffect } from "react";
import { useTheme, Card, Badge, Btn, Lbl, Mono, Ico, ICONS, SP } from "../components/ui";
import QRCode from "../components/QRCode";
import { rpc } from "../utils/rpc";

// ── Receive — redesigned 2026-05-17 ───────────────────────────────────
//
// Hierarchy:
//   1. QR hero — centered, large (220px), the thing scanners point at
//   2. Address row — full address with prominent copy
//   3. Amount request (optional) — encodes amount in QR via the
//      `coincync:<addr>?amount=X` URI scheme, so the recipient's
//      sender knows the expected payment size without out-of-band coord
//   4. Privacy badges — 3 chips reinforcing the stealth posture
//   5. Collapsible "how stealth addresses work" educational text
//
// Removed: "New Address" button — was misleading (it re-called
// getWalletAddress() which returns the same address every time, not a
// fresh subaddress). The Addresses page handles real subaddress
// generation; pointing there is more honest than pretending a
// non-functional button does something.

export default function Receive() {
  const T = useTheme();
  const [addr, setAddr] = useState("");
  const [loading, setLoading] = useState(true);
  const [copied, setCopied] = useState(false);
  const [amount, setAmount] = useState("");
  const [showWhy, setShowWhy] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const a = await rpc.getWalletAddress();
        if (a) setAddr(a);
      } catch {}
      setLoading(false);
    })();
  }, []);

  function copy(text) {
    if (navigator.clipboard) {
      navigator.clipboard.writeText(text).then(() => {
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      });
    } else {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      document.body.removeChild(ta);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }

  // Build the QR payload — bare address if no amount, otherwise the
  // coincync: URI scheme that wallets parsing the QR can decode.
  const amountNum = parseFloat(amount) || 0;
  const qrPayload = addr
    ? (amountNum > 0 ? `coincync:${addr}?amount=${amountNum}` : addr)
    : "";

  // ── Loading ────────────────────────────────────────────────────
  if (loading) {
    return (
      <div style={{
        animation: "fadeIn .25s ease",
        display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center",
        minHeight: 360, gap: 14, color: T.t3,
      }}>
        <div style={{
          width: 32, height: 32,
          border: `2px solid ${T.ac2}`, borderTopColor: "transparent",
          borderRadius: "50%", animation: "spin .7s linear infinite",
        }}/>
        <span style={{ fontSize: 12, fontFamily: T.mono }}>Loading wallet address…</span>
      </div>
    );
  }

  // ── Main ────────────────────────────────────────────────────────
  return (
    <div style={{ animation: "fadeIn .25s ease", maxWidth: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: SP.lg }}>
        <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t3, letterSpacing: ".14em", textTransform: "uppercase" }}>
          Receive CYNC
        </div>
        <h1 style={{ fontFamily: T.serif, fontSize: 22, fontWeight: 400, marginTop: 2 }}>
          Share to get paid
        </h1>
      </div>

      {/* ═══ QR hero ═══ */}
      <Card style={{
        marginBottom: SP.lg,
        padding: "28px 26px 22px",
        background: `linear-gradient(135deg, ${T.card} 0%, ${T.ac2}06 60%, ${T.card} 100%)`,
        border: `1px solid ${T.ac2}28`,
        position: "relative", overflow: "hidden",
      }}>
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 2,
          background: `linear-gradient(90deg, transparent, ${T.ac2}, transparent)`,
          opacity: 0.6,
        }}/>

        {/* QR centered */}
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 18 }}>
          <div style={{
            padding: 12,
            background: "#FFFFFF",
            borderRadius: 12,
            border: `1px solid ${T.ac2}30`,
            boxShadow: `0 4px 20px ${T.ac2}15`,
          }}>
            <QRCode value={qrPayload} size={220}/>
          </div>
        </div>

        {/* Hint about what the QR encodes */}
        {amountNum > 0 && (
          <div style={{
            textAlign: "center", marginBottom: 12,
            fontSize: 10, fontFamily: T.mono, color: T.amber,
          }}>
            QR encodes: <strong>{amountNum} CYNC</strong> payment request
          </div>
        )}

        {/* Address row */}
        <div style={{
          background: T.bg, border: `1px solid ${T.b}`,
          borderRadius: 10, padding: "12px 14px",
          cursor: "pointer", userSelect: "all", wordBreak: "break-all",
          transition: "border-color .15s",
        }}
          onClick={() => copy(addr)}
          onMouseEnter={e => e.currentTarget.style.borderColor = `${T.ac2}50`}
          onMouseLeave={e => e.currentTarget.style.borderColor = T.b}>
          <div style={{ fontSize: 10, color: T.t3, marginBottom: 4, fontFamily: T.mono, letterSpacing: ".08em", textTransform: "uppercase" }}>
            Your stealth address
          </div>
          <Mono size={11} color={T.ac2}>{addr}</Mono>
        </div>

        {/* Copy button + badges row */}
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginTop: 14, gap: 12, flexWrap: "wrap" }}>
          <Btn onClick={() => copy(addr)} small>
            <Ico d={copied ? ICONS.check : ICONS.copy} size={12} color="#000"/>
            {copied ? "Copied!" : "Copy address"}
          </Btn>
          <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
            <Badge label="Stealth · 1-time" color={T.ac2}/>
            <Badge label="Ristretto255" color={T.ac2}/>
            <Badge label="View tag · 1-byte" color={T.green}/>
          </div>
        </div>
      </Card>

      {/* ═══ Amount request (optional) ═══ */}
      <Card style={{ marginBottom: SP.lg, padding: "14px 18px" }}>
        <Lbl>
          Request a specific amount <span style={{ color: T.t3, fontWeight: 400, fontSize: 10 }}>(optional · embeds into the QR code)</span>
        </Lbl>
        <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
          <input value={amount}
            onChange={e => setAmount(e.target.value.replace(/[^0-9.]/g, ""))}
            placeholder="e.g. 5.0"
            style={{
              flex: 1, padding: "10px 12px", borderRadius: 8,
              background: T.bg, color: T.t1, outline: "none",
              border: `1px solid ${T.b}`,
              fontFamily: T.mono, fontSize: 12,
            }}/>
          {amount && (
            <Btn small variant="ghost" onClick={() => setAmount("")}>Clear</Btn>
          )}
        </div>
        {amountNum > 0 && (
          <div style={{ marginTop: 10, padding: "8px 12px", background: T.bg, borderRadius: 7, border: `1px solid ${T.b}` }}>
            <div style={{ fontSize: 9, color: T.t3, fontFamily: T.mono, letterSpacing: ".08em", textTransform: "uppercase", marginBottom: 3 }}>
              Payment URI
            </div>
            <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t2, wordBreak: "break-all" }}>
              {qrPayload}
            </div>
            <button onClick={() => copy(qrPayload)} style={{
              marginTop: 6, background: "none", border: "none",
              color: T.ac2, fontSize: 10, fontWeight: 600,
              cursor: "pointer", display: "inline-flex", alignItems: "center", gap: 4,
              padding: 0, fontFamily: T.mono,
            }}>
              <Ico d={ICONS.copy} size={10} color={T.ac2}/>
              Copy URI
            </button>
          </div>
        )}
      </Card>

      {/* ═══ Collapsible educational text ═══ */}
      <button onClick={() => setShowWhy(!showWhy)} style={{
        background: "none", border: "none", color: T.t3,
        fontSize: 10, fontWeight: 600, cursor: "pointer",
        fontFamily: T.mono, letterSpacing: ".1em", textTransform: "uppercase",
        display: "flex", alignItems: "center", gap: 6, padding: "8px 0",
        width: "100%", justifyContent: "center",
      }}>
        {showWhy ? "Hide" : "How stealth addresses work"}
        <span style={{ fontSize: 9 }}>{showWhy ? "▾" : "▸"}</span>
      </button>
      {showWhy && (
        <Card style={{ padding: "14px 18px", animation: "fadeIn .15s ease" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 10 }}>
            <Ico d={ICONS.lock} size={14} color={T.ac2}/>
            <div style={{ fontFamily: T.serif, fontSize: 14, fontWeight: 400 }}>
              Stealth addresses
            </div>
          </div>
          <div style={{ fontSize: 11, color: T.t2, lineHeight: 1.6, marginBottom: 10 }}>
            Each sender derives a unique one-time public key from your stealth address. The actual destination key never appears on-chain — only the sender and you can link the payment. This means you can share your stealth address publicly (on a website, profile, business card, etc.) without compromising the privacy of any individual payment.
          </div>
          <div style={{ fontSize: 11, color: T.t2, lineHeight: 1.6 }}>
            Need multiple addresses for accounting (e.g. one per customer)? The wallet supports <strong>subaddresses</strong> derived from your spend/view keys — see the Addresses page.
          </div>
        </Card>
      )}
    </div>
  );
}
