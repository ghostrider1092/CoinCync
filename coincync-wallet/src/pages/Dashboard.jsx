import { useContext, useState } from "react";
import { useTheme, Card, Badge, Ico, ICONS, SP } from "../components/ui";
import { WalletCtx, NavCtx } from "../appContexts";
import { rpc } from "../utils/rpc";

// ── Dashboard — redesigned 2026-05-16 ──────────────────────────────
//
// Hierarchy (top-to-bottom = most-to-least important):
//   1. Balance hero with inline quick actions (Send / Receive / Mine / Scan)
//   2. Live network panel (height / peers / hashrate) + Recent Activity
//   3. Privacy summary band (22 layers, link to full Privacy page)
//   4. Constitutional footer (single small italic line)
//
// What got removed from the previous Dashboard:
//   - Globe3D (purely decorative, took 220px of prime real estate, no
//     live data). Future: re-home on a dedicated Network/Globe page.
//   - Six static-constant StatCards (Supply Cap "100M", Ring Size "11",
//     Fee Burn "30%", Tail Emission, Dev Tax, etc.). These never
//     change — moved to the Supply Audit page where deep constants
//     belong. Dashboard shows live data only.
//   - Full 22-layer privacy matrix as always-visible block. Compressed
//     into a single status band with a "View detail" link to the
//     Privacy page (which already lists all 22 with descriptions).

const PRIVACY_LAYERS = [
  { label: "L1 Cryptographic",   count: 7, color: "ac2"   },
  { label: "L2 Network",          count: 4, color: "blue"  },
  { label: "L3 Wallet",           count: 7, color: "amber" },
  { label: "L4 Constitutional",   count: 4, color: "red"   },
];

export default function Dashboard() {
  const T = useTheme();
  const { navigateTo } = useContext(NavCtx);
  const { balance, syncInfo, txs, mining, scanning, scanResult, scanWallet } =
    useContext(WalletCtx);

  const synced = syncInfo.syncPct >= 99.9;
  const heightLabel = syncInfo.height?.toLocaleString() || "—";
  const peerCount = syncInfo.peers ?? "—";
  const hashrate = mining?.is_mining ? `${Math.round(mining.hashrate || 0)} H/s` : "—";

  // Balance display split into whole, fractional, suffix.
  const balanceParts = (() => {
    const raw = balance?.total;
    if (!raw || raw === "—") return { whole: "0", frac: "0000", suffix: "CYNC", isZero: true };
    const [whole, frac = ""] = String(raw).split(".");
    return { whole, frac: frac.padEnd(4, "0").slice(0, 4), suffix: "CYNC", isZero: parseFloat(raw) === 0 };
  })();

  return (
    <div style={{ animation: "fadeIn .25s ease", maxWidth: "100%" }}>
      {/* ═══ Header strip ═══ */}
      <div style={{
        display: "flex", alignItems: "baseline", justifyContent: "space-between",
        marginBottom: SP.lg,
      }}>
        <div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t3, letterSpacing: ".14em", textTransform: "uppercase" }}>
            Welcome back
          </div>
          <h1 style={{ fontFamily: T.serif, fontSize: 22, fontWeight: 400, letterSpacing: -.01, marginTop: 2 }}>
            Dashboard
          </h1>
        </div>
        {/* Scan + scan-result float-right */}
        <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
          {scanResult && (
            <span style={{
              fontSize: 10, color: T.t3, fontFamily: T.mono,
              maxWidth: 240, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
            }}>{scanResult}</span>
          )}
          <button onClick={scanWallet} disabled={scanning} style={{
            display: "inline-flex", alignItems: "center", gap: 6,
            padding: "6px 11px", fontSize: 10, fontWeight: 600,
            background: T.acb, border: `1px solid ${T.ac2}30`,
            borderRadius: 999, color: T.ac2,
            cursor: scanning ? "wait" : "pointer", transition: "all .15s",
          }}>
            <Ico d={ICONS.refresh} size={11} color={T.ac2}/>
            {scanning ? "Scanning…" : "Scan wallet"}
          </button>
        </div>
      </div>

      {/* ═══ Balance hero with inline actions ═══ */}
      <Card style={{
        marginBottom: SP.lg,
        padding: "22px 26px 18px",
        background: `linear-gradient(135deg, ${T.card} 0%, ${T.ac2}08 60%, ${T.card} 100%)`,
        border: `1px solid ${T.ac2}28`,
        position: "relative",
        overflow: "hidden",
      }}>
        {/* Decorative gradient line top-edge — subtle visual anchor */}
        <div style={{
          position: "absolute", top: 0, left: 0, right: 0, height: 2,
          background: `linear-gradient(90deg, transparent, ${T.ac2}, transparent)`,
          opacity: 0.6,
        }}/>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 24, marginBottom: 18 }}>
          <div style={{ minWidth: 0 }}>
            <div style={{
              fontSize: 10, fontWeight: 600, color: T.t3, letterSpacing: ".12em",
              textTransform: "uppercase", marginBottom: 8,
            }}>Total balance</div>
            <div style={{
              fontFamily: T.mono, fontSize: 38, fontWeight: 600,
              color: balanceParts.isZero ? T.t3 : T.ac2,
              letterSpacing: -.5, lineHeight: 1,
            }}>
              {balanceParts.whole}
              <span style={{ fontSize: 22, fontWeight: 400, color: T.t2 }}>
                .{balanceParts.frac}
              </span>
              <span style={{ fontSize: 14, fontWeight: 400, color: T.t3, marginLeft: 10 }}>
                {balanceParts.suffix}
              </span>
            </div>
            <div style={{ marginTop: 8, fontSize: 11, color: T.t3, display: "flex", gap: 12, alignItems: "center", flexWrap: "wrap" }}>
              <span>
                {txs.length} transaction{txs.length !== 1 ? "s" : ""}
              </span>
              <span style={{ color: T.t3 }}>·</span>
              <span style={{
                display: "inline-flex", alignItems: "center", gap: 5,
                color: synced ? T.green : T.amber,
                fontFamily: T.mono, fontSize: 10,
              }}>
                <span style={{
                  width: 6, height: 6, borderRadius: "50%",
                  background: synced ? T.green : T.amber,
                  boxShadow: synced ? `0 0 6px ${T.green}80` : `0 0 6px ${T.amber}80`,
                }}/>
                {synced ? "Synced" : "Syncing"} · block {heightLabel}
              </span>
              {mining?.is_mining && (
                <>
                  <span style={{ color: T.t3 }}>·</span>
                  <span style={{ display: "inline-flex", alignItems: "center", gap: 5, color: T.amber, fontFamily: T.mono, fontSize: 10 }}>
                    <Ico d={ICONS.mining} size={10} color={T.amber}/>
                    {hashrate}
                  </span>
                </>
              )}
            </div>
          </div>
        </div>

        {/* Inline quick-action row */}
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(4, 1fr)",
          gap: 8, marginTop: 4,
        }}>
          <ActionButton icon={ICONS.send}    label="Send"     onClick={() => navigateTo("send")}    T={T} accent="ac2"/>
          <ActionButton icon={ICONS.receive} label="Receive"  onClick={() => navigateTo("receive")} T={T} accent="green"/>
          <ActionButton icon={ICONS.mining}  label="Mine"     onClick={() => navigateTo("mining")}  T={T} accent="amber"/>
          <ActionButton icon={ICONS.history} label="History"  onClick={() => navigateTo("history")} T={T} accent="blue"/>
        </div>
      </Card>

      {/* ═══ Network panel + Recent Activity (2-col) ═══ */}
      <div style={{
        display: "grid", gridTemplateColumns: "minmax(180px, 0.4fr) 1fr",
        gap: SP.lg, marginBottom: SP.lg,
      }}>
        {/* Live network panel */}
        <Card style={{ padding: "16px 18px" }}>
          <div style={{ fontSize: 10, fontWeight: 700, color: T.t3, letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 14 }}>
            Network
          </div>
          <NetworkStat label="Block"      value={heightLabel}  T={T} mono/>
          <NetworkStat label="Peers"      value={peerCount}    T={T} mono accent={peerCount > 0 ? T.green : T.amber}/>
          <NetworkStat label="Hashrate"   value={hashrate}     T={T} mono accent={mining?.is_mining ? T.amber : T.t3} last/>
        </Card>

        {/* Recent activity */}
        <Card style={{ padding: "16px 18px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <div style={{ fontSize: 10, fontWeight: 700, color: T.t3, letterSpacing: ".1em", textTransform: "uppercase" }}>
              Recent activity
            </div>
            {txs.length > 4 && (
              <button onClick={() => navigateTo("history")} style={{
                background: "none", border: "none", color: T.ac2, fontSize: 10,
                cursor: "pointer", fontFamily: T.mono,
              }}>
                view all →
              </button>
            )}
          </div>
          {txs.length === 0 ? (
            <EmptyActivity T={T}/>
          ) : (
            <div>
              {txs.slice(0, 5).map(tx => (
                <ActivityRow key={tx.id} tx={tx} T={T}/>
              ))}
            </div>
          )}
        </Card>
      </div>

      {/* ═══ Privacy summary band ═══ */}
      <Card style={{
        padding: "14px 20px", marginBottom: SP.lg,
        cursor: "pointer", transition: "border-color .15s",
      }} onClick={() => navigateTo("privacy")}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 16 }}>
          <div>
            <div style={{ fontSize: 10, fontWeight: 700, color: T.t3, letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 4 }}>
              Privacy stack
            </div>
            <div style={{ fontFamily: T.serif, fontSize: 16, color: T.t1 }}>
              22 layers active across 4 tiers
            </div>
          </div>
          <div style={{ display: "flex", gap: 12, alignItems: "center" }}>
            {PRIVACY_LAYERS.map(layer => (
              <div key={layer.label} style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <span style={{
                  width: 7, height: 7, borderRadius: "50%",
                  background: T[layer.color] || T.ac2,
                  boxShadow: `0 0 4px ${T[layer.color] || T.ac2}60`,
                }}/>
                <span style={{ fontSize: 10, color: T.t2, fontFamily: T.mono }}>
                  {layer.label.split(" ")[0]} <span style={{ color: T.t3 }}>·{layer.count}</span>
                </span>
              </div>
            ))}
            <span style={{ color: T.ac2, fontSize: 11, fontFamily: T.mono, marginLeft: 4 }}>
              view detail →
            </span>
          </div>
        </div>
      </Card>

      {/* ═══ Constitutional footer ═══ */}
      <div style={{ textAlign: "center", padding: "14px 0 6px", marginTop: SP.md }}>
        <div style={{
          fontFamily: T.serif, fontStyle: "italic", fontSize: 11,
          color: T.t3, lineHeight: 1.5, maxWidth: 460, margin: "0 auto",
        }}>
          Private by law. Private by math.
        </div>
        <div style={{
          fontFamily: T.mono, fontSize: 9, color: T.t3,
          marginTop: 4, letterSpacing: ".15em",
        }}>
          THE COINCYNC MANIFESTO
        </div>
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────

function ActionButton({ icon, label, onClick, T, accent = "ac2" }) {
  const color = T[accent] || T.ac2;
  return (
    <button onClick={onClick} style={{
      display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
      padding: "11px 14px", fontSize: 12, fontWeight: 600,
      background: T.bg, border: `1px solid ${T.b}`,
      borderRadius: 10, color: T.t1, cursor: "pointer",
      transition: "all .15s ease",
    }}
      onMouseEnter={e => {
        e.currentTarget.style.borderColor = color;
        e.currentTarget.style.background = `${color}08`;
        e.currentTarget.style.color = color;
      }}
      onMouseLeave={e => {
        e.currentTarget.style.borderColor = T.b;
        e.currentTarget.style.background = T.bg;
        e.currentTarget.style.color = T.t1;
      }}>
      <Ico d={icon} size={13} color="currentColor"/>
      {label}
    </button>
  );
}

function NetworkStat({ label, value, T, mono = false, accent, last = false }) {
  return (
    <div style={{
      padding: "8px 0",
      borderBottom: last ? "none" : `1px solid ${T.b}`,
    }}>
      <div style={{ fontSize: 9, color: T.t3, letterSpacing: ".1em", textTransform: "uppercase", marginBottom: 3 }}>
        {label}
      </div>
      <div style={{
        fontFamily: mono ? T.mono : T.serif,
        fontSize: mono ? 14 : 17, fontWeight: mono ? 600 : 400,
        color: accent || T.t1,
      }}>
        {value}
      </div>
    </div>
  );
}

function ActivityRow({ tx, T }) {
  const received = tx.type === "received";
  const accent = received ? T.green : T.red;
  return (
    <div style={{
      display: "flex", alignItems: "center", justifyContent: "space-between",
      padding: "8px 0", borderBottom: `1px solid ${T.b}`,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{
          width: 28, height: 28, borderRadius: 8,
          background: `${accent}12`, border: `1px solid ${accent}25`,
          display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
        }}>
          <Ico d={received ? ICONS.arrowDown : ICONS.arrowUp} size={13} color={accent}/>
        </div>
        <div>
          <div style={{ fontSize: 12, fontWeight: 500, color: T.t1 }}>
            {received ? "Received" : "Sent"}
          </div>
          <div style={{ fontSize: 10, color: T.t3, fontFamily: T.mono }}>
            block {tx.height}
          </div>
        </div>
      </div>
      <div style={{
        fontFamily: T.mono, fontSize: 13, fontWeight: 600, color: accent,
      }}>
        {received ? "+" : "−"}{parseFloat(tx.amount).toFixed(2)} CYNC
      </div>
    </div>
  );
}

function EmptyActivity({ T }) {
  return (
    <div style={{ padding: "20px 0", textAlign: "center" }}>
      <div style={{ fontSize: 12, color: T.t3, marginBottom: 12 }}>
        No transactions yet. Get some testnet CYNC to start:
      </div>
      <button onClick={async () => {
        try {
          const walletAddr = await rpc.getWalletAddress();
          if (!walletAddr) { alert("Could not get wallet address. Open the Receive page first."); return; }
          const resp = await fetch("https://explorer.coincync.network/faucet/", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ address: walletAddr }),
          });
          const d = await resp.json();
          if (d.success) alert("Faucet sent 10 CYNC. Click 'Scan wallet' to see it.");
          else alert(d.error || "Faucet request failed");
        } catch {
          alert("Faucet unavailable — try the explorer faucet at explorer.coincync.network");
        }
      }} style={{
        padding: "8px 16px", fontSize: 11, fontWeight: 600,
        background: T.acb, border: `1px dashed ${T.ac2}50`,
        borderRadius: 8, color: T.ac2, cursor: "pointer",
        transition: "all .15s",
      }}
        onMouseEnter={e => e.currentTarget.style.background = `${T.ac2}15`}
        onMouseLeave={e => e.currentTarget.style.background = T.acb}>
        Get 10 free testnet CYNC from the faucet
      </button>
    </div>
  );
}
