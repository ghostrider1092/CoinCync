import { useState, useContext, useEffect, useMemo } from "react";
import { useTheme, Card, Badge, Btn, Ico, ICONS, EmptyState, SP } from "../components/ui";
import TxModal from "../components/TxModal";
import { WalletCtx, NotifCtx } from "../appContexts";

// ── History — redesigned 2026-05-17 ───────────────────────────────────
//
// Hierarchy:
//   1. Header — eyebrow + Fraunces title + filter-aware count + CSV
//   2. Filters strip — search input + direction + type + date range
//      (date range was declared but never wired in the prior design)
//   3. Date-grouped tx list (Today / Yesterday / This week / Earlier)
//      so a wallet with hundreds of txs is scannable
//   4. Row design: icon + txid/memo (left) + amount (right) + date+type
//      pill — same vertical weight on each row, no cramped grid
//
// Kept intentionally from prior design:
//   - Right-click / long-press context menu with copy/explorer/etc
//     (clever, useful, animated nicely)
//   - CSV export
//   - TxModal click-through for full detail (separate component)
//   - All search / filter logic; just added date filters to it

export default function History() {
  const T = useTheme();
  const { txs } = useContext(WalletCtx);
  const { push } = useContext(NotifCtx);
  const [search, setSearch]       = useState("");
  const [dirFilter, setDirFilter] = useState("all");
  const [typeFilter, setType]     = useState("all");
  const [dateFrom, setDateFrom]   = useState("");
  const [dateTo, setDateTo]       = useState("");
  const [selectedTx, setSelectedTx] = useState(null);
  const [ctxMenu, setCtxMenu]     = useState(null);

  // Context menu — closes on outside click / escape / scroll.
  useEffect(() => {
    if (!ctxMenu) return;
    const close = () => setCtxMenu(null);
    const onKey = (e) => { if (e.key === "Escape") setCtxMenu(null); };
    window.addEventListener("click", close);
    window.addEventListener("scroll", close, true);
    window.addEventListener("keydown", onKey);
    return () => {
      window.removeEventListener("click", close);
      window.removeEventListener("scroll", close, true);
      window.removeEventListener("keydown", onKey);
    };
  }, [ctxMenu]);

  function copy(text, label) {
    try { navigator.clipboard.writeText(text); push(`${label} copied`, "success"); }
    catch (_) { push("Copy failed", "error"); }
  }

  // Filter the tx list once per render.
  const filtered = useMemo(() => txs.filter(tx => {
    if (dirFilter  !== "all" && tx.type   !== dirFilter)  return false;
    if (typeFilter !== "all" && tx.txType !== typeFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const hay = `${tx.id} ${tx.amount} ${tx.memo || ""}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (dateFrom) {
      const txDate = (tx.date || "").split(" ")[0];
      if (txDate < dateFrom) return false;
    }
    if (dateTo) {
      const txDate = (tx.date || "").split(" ")[0];
      if (txDate > dateTo) return false;
    }
    return true;
  }), [txs, dirFilter, typeFilter, search, dateFrom, dateTo]);

  // Group filtered txs by date-relative bucket.
  const grouped = useMemo(() => groupByDateBucket(filtered), [filtered]);

  function clearFilters() {
    setSearch(""); setDirFilter("all"); setType("all");
    setDateFrom(""); setDateTo("");
  }

  const anyFilterActive = !!(search || dirFilter !== "all" || typeFilter !== "all" || dateFrom || dateTo);

  function exportCSV() {
    const rows = [
      ["txid","direction","type","amount","date","height","fee","memo"],
      ...filtered.map(t => [t.id, t.type, t.txType, t.amount, t.date, t.height, t.fee, t.memo || ""]),
    ];
    const csv = rows.map(r => r.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(",")).join("\n");
    const a = document.createElement("a");
    a.href = "data:text/csv;charset=utf-8," + encodeURIComponent(csv);
    a.download = `coincync_history_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    push(`Exported ${filtered.length} transactions`, "success");
  }

  return (
    <div style={{ animation: "fadeIn .25s ease", maxWidth: "100%" }}>
      {/* ═══ Header ═══ */}
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-end", marginBottom: SP.lg, gap: 12, flexWrap: "wrap" }}>
        <div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t3, letterSpacing: ".14em", textTransform: "uppercase" }}>
            Transactions
          </div>
          <h1 style={{ fontFamily: T.serif, fontSize: 22, fontWeight: 400, marginTop: 2 }}>
            History
          </h1>
          <div style={{ fontSize: 11, color: T.t3, marginTop: 4 }}>
            {anyFilterActive
              ? <>Showing <strong style={{ color: T.t2 }}>{filtered.length}</strong> of {txs.length} {pl(txs.length, "transaction")}</>
              : <><strong style={{ color: T.t2 }}>{txs.length}</strong> {pl(txs.length, "transaction")}</>
            }
          </div>
        </div>
        <Btn variant="ghost" small onClick={exportCSV} disabled={filtered.length === 0}>
          <Ico d={ICONS.copy} size={12} color={T.ac2}/>
          Export CSV
        </Btn>
      </div>

      {/* ═══ Filters ═══ */}
      <Card style={{ marginBottom: SP.lg, padding: "14px 18px" }}>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center" }}>
          <input value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search txid, amount, or memo…"
            style={{
              flex: "1 1 240px", minWidth: 200,
              padding: "8px 12px", borderRadius: 8,
              background: T.bg, color: T.t1, outline: "none",
              border: `1px solid ${T.b}`,
              fontSize: 12,
            }}/>
          <FilterPills label="Direction" value={dirFilter} onChange={setDirFilter} options={["all", "received", "sent"]} T={T} accent={T.green}/>
          <FilterPills label="Type"      value={typeFilter} onChange={setType}      options={["all", "ring", "shielded", "coinbase"]} T={T} accent={T.blue}/>
        </div>
        <div style={{ display: "flex", flexWrap: "wrap", gap: 10, alignItems: "center", marginTop: 10 }}>
          <DateInput label="From" value={dateFrom} onChange={setDateFrom} T={T}/>
          <DateInput label="To"   value={dateTo}   onChange={setDateTo}   T={T}/>
          {anyFilterActive && (
            <button onClick={clearFilters} style={{
              background: "none", border: "none", color: T.ac2,
              fontSize: 11, fontWeight: 600, cursor: "pointer",
              fontFamily: T.mono, padding: "4px 8px",
            }}>
              Clear filters
            </button>
          )}
        </div>
      </Card>

      {/* ═══ Grouped tx list ═══ */}
      {filtered.length === 0 ? (
        <Card style={{ padding: 0 }}>
          <EmptyState
            icon={ICONS.history}
            title={txs.length === 0 ? "No transactions yet" : "No matching transactions"}
            subtitle={txs.length === 0
              ? "Mine CYNC or use the faucet to receive your first transaction."
              : "Try adjusting your search or filters."}/>
        </Card>
      ) : (
        grouped.map(group => (
          <div key={group.label} style={{ marginBottom: SP.lg }}>
            <div style={{
              fontSize: 9, fontWeight: 700, color: T.t3,
              letterSpacing: ".14em", textTransform: "uppercase",
              padding: "0 4px 6px", fontFamily: T.mono,
            }}>
              {group.label} <span style={{ color: T.t3, fontWeight: 400 }}>· {group.txs.length}</span>
            </div>
            <Card style={{ padding: 0, overflow: "hidden" }}>
              {group.txs.map((tx, i) => (
                <TxRow key={tx.id} tx={tx} T={T}
                  onClick={() => setSelectedTx(tx)}
                  onContextMenu={e => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY, tx }); }}
                  last={i === group.txs.length - 1}/>
              ))}
            </Card>
          </div>
        ))
      )}

      {selectedTx && <TxModal tx={selectedTx} onClose={() => setSelectedTx(null)}/>}

      {ctxMenu && <ContextMenu ctxMenu={ctxMenu} T={T} copy={copy} onClose={() => setCtxMenu(null)}/>}
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────

function FilterPills({ label, value, onChange, options, T, accent }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{ fontSize: 9, color: T.t3, fontFamily: T.mono, letterSpacing: ".1em", textTransform: "uppercase" }}>
        {label}
      </span>
      <div style={{ display: "flex", gap: 4 }}>
        {options.map(opt => {
          const on = value === opt;
          return (
            <button key={opt} onClick={() => onChange(opt)} style={{
              padding: "5px 10px", borderRadius: 6, cursor: "pointer",
              border: `1px solid ${on ? accent : T.b}`,
              background: on ? `${accent}10` : T.bg,
              fontSize: 10, fontWeight: 600,
              color: on ? accent : T.t2,
              textTransform: "capitalize",
              transition: "all .12s",
            }}>
              {opt}
            </button>
          );
        })}
      </div>
    </div>
  );
}

function DateInput({ label, value, onChange, T }) {
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
      <span style={{ fontSize: 9, color: T.t3, fontFamily: T.mono, letterSpacing: ".1em", textTransform: "uppercase" }}>
        {label}
      </span>
      <input type="date" value={value} onChange={e => onChange(e.target.value)}
        style={{
          padding: "5px 8px", borderRadius: 6,
          background: T.bg, color: value ? T.t1 : T.t3, outline: "none",
          border: `1px solid ${value ? T.ac2 : T.b}`,
          fontSize: 11, fontFamily: T.mono,
          colorScheme: "dark",
        }}/>
      {value && (
        <button onClick={() => onChange("")} style={{
          background: "none", border: "none", color: T.t3,
          fontSize: 12, cursor: "pointer", padding: "0 4px",
        }} title="Clear">×</button>
      )}
    </div>
  );
}

function TxRow({ tx, T, onClick, onContextMenu, last }) {
  const received = tx.type === "received";
  const accent = received ? T.green : T.red;
  const typeColor = tx.txType === "shielded" ? T.blue : tx.txType === "coinbase" ? T.amber : T.ac2;
  const timeStr = (tx.date || "").split(" ")[1] || "";
  return (
    <div onClick={onClick} onContextMenu={onContextMenu}
      style={{
        display: "grid", gridTemplateColumns: "1fr auto",
        gap: 14, padding: "12px 16px",
        borderBottom: last ? "none" : `1px solid ${T.b}`,
        cursor: "pointer", transition: "background .1s",
      }}
      onMouseEnter={e => e.currentTarget.style.background = T.bg}
      onMouseLeave={e => e.currentTarget.style.background = ""}>
      <div style={{ display: "flex", alignItems: "center", gap: 12, minWidth: 0 }}>
        <div style={{
          width: 32, height: 32, borderRadius: 9,
          background: `${accent}12`, border: `1px solid ${accent}25`,
          display: "flex", alignItems: "center", justifyContent: "center", flexShrink: 0,
        }}>
          <Ico d={received ? ICONS.arrowDown : ICONS.arrowUp} size={14} color={accent}/>
        </div>
        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 12, fontWeight: 500, color: T.t1 }}>
              {received ? "Received" : "Sent"}
            </span>
            <Badge label={tx.txType} color={typeColor}/>
          </div>
          <div style={{ fontFamily: T.mono, fontSize: 10, color: T.t3, marginTop: 3, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {tx.id}
          </div>
          {tx.memo && (
            <div style={{ fontSize: 10, color: T.t2, marginTop: 3, fontStyle: "italic" }}>
              "{tx.memo}"
            </div>
          )}
        </div>
      </div>
      <div style={{ textAlign: "right", flexShrink: 0 }}>
        <div style={{ fontFamily: T.mono, fontSize: 13, fontWeight: 600, color: accent }}>
          {received ? "+" : "−"}{parseFloat(tx.amount).toFixed(4)} CYNC
        </div>
        <div style={{ fontSize: 10, color: T.t3, marginTop: 3, fontFamily: T.mono }}>
          {timeStr || (tx.date || "").split(" ")[0]} · block {tx.height}
        </div>
      </div>
    </div>
  );
}

function ContextMenu({ ctxMenu, T, copy, onClose }) {
  const items = [
    { label: "Copy txid",        hint: "⌘C",          run: () => copy(ctxMenu.tx.id, "Tx ID") },
    { label: "Copy amount",      hint: ctxMenu.tx.amount, run: () => copy(ctxMenu.tx.amount, "Amount") },
    { label: "View on explorer", hint: "↗",           run: () => window.open(`https://explorer.coincync.network/tx/${ctxMenu.tx.id}`, "_blank", "noopener") },
  ];
  const W = 220, H = items.length * 32 + 12;
  const x = Math.min(ctxMenu.x, window.innerWidth - W - 8);
  const y = Math.min(ctxMenu.y, window.innerHeight - H - 8);
  return (
    <div onClick={e => e.stopPropagation()}
      style={{
        position: "fixed", left: x, top: y, zIndex: 1000, minWidth: W,
        background: T.s1 || T.bg, border: `1px solid ${T.b}`,
        boxShadow: "0 12px 32px rgba(0,0,0,.45)", borderRadius: 8, padding: 6,
        transformOrigin: "top left", animation: "ctxOpen .2s ease-out forwards",
      }}>
      <style>{`
        @keyframes ctxOpen { from { opacity:0; transform:scale(.94) translateY(-4px); } to { opacity:1; transform:scale(1) translateY(0); } }
        @keyframes ctxItemIn { from { opacity:0; transform:translateX(-6px); } to { opacity:1; transform:translateX(0); } }
      `}</style>
      {items.map((it, i) => (
        <div key={it.label}
          onClick={() => { it.run(); onClose(); }}
          style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "8px 12px", fontSize: 12, color: T.t2, cursor: "pointer",
            borderRadius: 6,
            opacity: 0, animation: `ctxItemIn .25s ease-out forwards`,
            animationDelay: `${0.05 + i * 0.06}s`,
            transition: "background .12s, color .12s",
          }}
          onMouseEnter={e => { e.currentTarget.style.background = T.bg; e.currentTarget.style.color = T.ac2; }}
          onMouseLeave={e => { e.currentTarget.style.background = "transparent"; e.currentTarget.style.color = T.t2; }}>
          <span>{it.label}</span>
          <span style={{
            fontFamily: T.mono, fontSize: 10, color: T.t3,
            marginLeft: 14, maxWidth: 120, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
          }}>{it.hint}</span>
        </div>
      ))}
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────

function pl(n, word) {
  return n === 1 ? word : `${word}s`;
}

function groupByDateBucket(txs) {
  // Group into Today / Yesterday / This week / Earlier buckets.
  // Assumes tx.date is "YYYY-MM-DD HH:MM:SS" or similar; uses just the date part.
  const today = new Date();
  const yYear = today.getFullYear(), yMonth = today.getMonth(), yDay = today.getDate();
  const dateOnly = (d) => new Date(d.getFullYear(), d.getMonth(), d.getDate());
  const todayD = dateOnly(today);
  const yesterdayD = new Date(todayD); yesterdayD.setDate(yesterdayD.getDate() - 1);
  const weekStartD = new Date(todayD); weekStartD.setDate(weekStartD.getDate() - 7);

  const buckets = {
    "Today":     [],
    "Yesterday": [],
    "This week": [],
    "Earlier":   [],
  };

  for (const tx of txs) {
    const datePart = (tx.date || "").split(" ")[0];
    if (!datePart) { buckets["Earlier"].push(tx); continue; }
    const [yy, mm, dd] = datePart.split("-").map(Number);
    if (!yy) { buckets["Earlier"].push(tx); continue; }
    const txD = new Date(yy, mm - 1, dd);

    if      (txD.getTime() === todayD.getTime())     buckets["Today"].push(tx);
    else if (txD.getTime() === yesterdayD.getTime()) buckets["Yesterday"].push(tx);
    else if (txD >= weekStartD)                       buckets["This week"].push(tx);
    else                                              buckets["Earlier"].push(tx);
  }

  // Return only non-empty buckets, preserving the canonical order.
  return Object.entries(buckets)
    .filter(([_, list]) => list.length > 0)
    .map(([label, list]) => ({ label, txs: list }));
}
