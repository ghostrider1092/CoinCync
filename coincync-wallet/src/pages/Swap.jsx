import React, { useState, useContext, useEffect } from "react";
import { useTheme, Card, Btn, Ico, Lbl, Input, Section, ICONS, SP } from "../components/ui";
import { rpc, isWalletBackendAvailable, formatWalletError } from "../utils/rpc";
import { NotifCtx } from "../appContexts";

// ── Atomic Swap (cyncswap / CIP-001) ──────────────────────────────────
//
// CYNC ↔ BTC atomic swap. Trust-minimised exchange — neither party
// hands custody to a centralized exchange. The protocol uses BIP-340
// adapter signatures + a cross-curve DLEQ proof to bind the same
// secret across secp256k1 (Bitcoin) and Ristretto255 (CoinCync).
//
// Wallet posture (v0.1): this page is a thin UI over the `cyncswap`
// CLI binary, mirroring how the multisig page calls `wallet_cli` as
// a subprocess. The cryptographic state machine lives in the
// `coincync-swap` crate; this page just orchestrates the operator
// flow and surfaces state transitions.
//
// Five-stage flow:
//
//   1. Setup       — pick role + amount; produce the handshake invite
//   2. Handshake   — exchange Noise XX keys + adaptor material with
//                    the counterparty (out-of-band today; coord-
//                    relayed in a later release)
//   3. Lock        — Bob broadcasts BTC lock tx; Alice waits N confs
//   4. Claim       — Alice's BTC claim reveals the adaptor secret;
//                    Bob extracts it and spends the CYNC lock
//   5. History     — read-only view of completed + refunded swaps
//
// Refund path (CSV-engaged, BIP-341 script-path) is automatic on
// timeout — no operator action required.

const TABS = [
  { id: "setup",     label: "1. Setup",     short: "Setup" },
  { id: "handshake", label: "2. Handshake", short: "HS" },
  { id: "lock",      label: "3. Lock",      short: "Lock" },
  { id: "claim",     label: "4. Claim",     short: "Claim" },
  { id: "history",   label: "5. History",   short: "Log" },
];

export default function Swap() {
  const T = useTheme();
  const { push } = useContext(NotifCtx);
  const [tab, setTab] = useState("setup");
  const [active, setActive] = useState([]);
  const [loadingActive, setLoadingActive] = useState(false);

  const backendOk = isWalletBackendAvailable();

  useEffect(() => {
    if (!backendOk) return;
    let cancelled = false;
    async function poll() {
      setLoadingActive(true);
      try {
        const list = await rpc.swap.list();
        if (!cancelled) setActive(list?.swaps || []);
      } catch (e) {
        // Backend may not yet implement swap_list; treat as empty.
        if (!cancelled) setActive([]);
      }
      if (!cancelled) setLoadingActive(false);
    }
    poll();
    const id = setInterval(poll, 10000);
    return () => { cancelled = true; clearInterval(id); };
  }, [backendOk]);

  return (
    <div style={{ animation: "fadeIn .2s ease", maxWidth: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: SP.lg }}>
        <h1 style={{ fontSize: 21, fontWeight: 700 }}>Atomic Swap</h1>
        <div style={{ fontSize: 11, color: T.t3, marginTop: 4 }}>
          Trust-minimised CYNC&nbsp;↔&nbsp;BTC exchange per <code>CIP-001</code>. No custodial exchange; either both legs settle or both refund.
        </div>
      </div>

      {/* Backend availability banner */}
      {!backendOk && (
        <div style={{
          padding: "12px 16px", marginBottom: 14,
          background: `${T.amber}12`, border: `1px solid ${T.amber}30`,
          borderRadius: 10, fontSize: 12, color: T.amber,
        }}>
          Atomic swap actions require the desktop Tauri backend. Open this app via <code>npx tauri dev</code> or the installer build &mdash; browser tabs can&rsquo;t shell out to the <code>cyncswap</code> binary.
        </div>
      )}

      {/* Active swaps summary */}
      <ActiveSwapsCard
        swaps={active}
        loading={loadingActive}
        backendOk={backendOk}
        onJump={(stage) => setTab(stage)}
      />

      {/* Tab bar */}
      <div style={{
        display: "flex", gap: SP.sm, marginBottom: SP.xl,
        borderBottom: `1px solid ${T.b}`, paddingBottom: 0, overflowX: "auto",
      }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)} style={{
            display: "flex", alignItems: "center", gap: 6, padding: "8px 14px",
            borderRadius: `${SP.md}px ${SP.md}px 0 0`, border: "none",
            background: tab === t.id ? `${T.ac2}12` : "transparent",
            color: tab === t.id ? T.ac2 : T.t3,
            fontSize: 11, fontWeight: tab === t.id ? 600 : 400,
            cursor: "pointer",
            borderBottom: tab === t.id ? `2px solid ${T.ac2}` : "2px solid transparent",
            transition: "all .15s", whiteSpace: "nowrap",
          }}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Active panel */}
      {tab === "setup"     && <SetupForm     push={push} backendOk={backendOk} onProgress={setTab} />}
      {tab === "handshake" && <HandshakeForm push={push} backendOk={backendOk} />}
      {tab === "lock"      && <LockForm      push={push} backendOk={backendOk} />}
      {tab === "claim"     && <ClaimForm     push={push} backendOk={backendOk} />}
      {tab === "history"   && <HistoryView   push={push} backendOk={backendOk} />}

      {/* Footer note */}
      <div style={{
        marginTop: SP.xxl, padding: "12px 16px",
        background: `${T.ac2}06`, borderLeft: `3px solid ${T.ac2}`,
        borderRadius: "0 8px 8px 0", fontSize: 11, color: T.t2, lineHeight: 1.6,
      }}>
        <strong style={{ color: T.ac2 }}>Trust model:</strong> the counterparty cannot steal funds. Worst case (counterparty disappears mid-swap): your funds return via the on-chain refund path after the CSV timeout. See <code>docs/cip/CIP-001-atomic-swap.md</code> for the protocol spec and <code>docs/cyncswap-audit-prep.md</code> for the security posture.
      </div>
    </div>
  );
}

// ── Active swaps summary ──────────────────────────────────────────────

function ActiveSwapsCard({ swaps, loading, backendOk, onJump }) {
  const T = useTheme();
  if (!backendOk) return null;
  if (!swaps || swaps.length === 0) {
    return (
      <div style={{
        padding: "10px 14px", marginBottom: SP.lg,
        background: T.bg, border: `1px solid ${T.b}`, borderRadius: 10,
        fontSize: 11, color: T.t3,
      }}>
        {loading ? "Checking active swaps…" : "No active swaps. Start one in the Setup tab below."}
      </div>
    );
  }
  return (
    <Card style={{ marginBottom: SP.lg }}>
      <div style={{ fontSize: 12, fontWeight: 600, marginBottom: SP.sm, color: T.t1 }}>
        Active swaps ({swaps.length})
      </div>
      {swaps.map(s => (
        <div key={s.id} style={{
          display: "flex", justifyContent: "space-between", alignItems: "center",
          padding: "8px 0", borderBottom: `1px solid ${T.b}`, fontSize: 11,
        }}>
          <div>
            <div style={{ color: T.t1, fontFamily: "'JetBrains Mono', monospace" }}>{s.id.slice(0, 12)}…</div>
            <div style={{ color: T.t3, marginTop: 2 }}>
              {s.role} · {s.amount} · {s.state}
            </div>
          </div>
          <Btn size="sm" onClick={() => onJump(s.next_stage || "lock")}>Continue</Btn>
        </div>
      ))}
    </Card>
  );
}

// ── 1. Setup ──────────────────────────────────────────────────────────

function SetupForm({ push, backendOk, onProgress }) {
  const T = useTheme();
  const [role, setRole] = useState("alice"); // alice = locks CYNC, gets BTC; bob = locks BTC, gets CYNC
  const [amount, setAmount] = useState("");
  const [btcAddress, setBtcAddress] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onStart() {
    if (!backendOk) return;
    const amt = parseFloat(amount);
    if (!(amt > 0)) {
      push("Amount must be a positive number", "warning");
      return;
    }
    if (role === "alice" && !btcAddress.trim()) {
      push("Alice needs the BTC receive address", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.swap.init({ role, amount: amt, btcAddress: btcAddress.trim() });
      setResult(r);
      push("Swap initialized — share the invite with your counterparty", "success");
    } catch (e) {
      push(formatWalletError(e, "Swap init failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Start a new atomic swap">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Pick your role + commit an amount. The wallet creates a fresh swap-id, generates
        the Noise XX static key, and produces an invite blob you hand to your
        counterparty. <strong>Funds do not move yet</strong> — locking happens after the
        handshake completes.
      </div>

      <Lbl>Role</Lbl>
      <div style={{ display: "flex", gap: SP.sm, marginBottom: SP.md }}>
        <RoleChip
          selected={role === "alice"}
          onClick={() => setRole("alice")}
          title="Alice"
          subtitle="Lock CYNC → receive BTC"
        />
        <RoleChip
          selected={role === "bob"}
          onClick={() => setRole("bob")}
          title="Bob"
          subtitle="Lock BTC → receive CYNC"
        />
      </div>

      <Input
        label={`Amount (${role === "alice" ? "CYNC" : "BTC"})`}
        value={amount} onChange={e => setAmount(e.target.value)} mono
        placeholder={role === "alice" ? "e.g. 100.0" : "e.g. 0.01"}
        hint="The exchange rate is negotiated out-of-band; this is just your leg's amount."
      />
      {role === "alice" && (
        <Input
          label="Your BTC receive address"
          value={btcAddress} onChange={e => setBtcAddress(e.target.value)} mono
          placeholder="bc1p… or tb1p… (taproot, P2TR)"
          hint="Must be a P2TR address for the network in BtcConfig (mainnet / testnet / regtest / signet)."
        />
      )}

      <Btn onClick={onStart} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Initializing…" : "Start swap"}
      </Btn>

      {result && (
        <div style={{
          marginTop: SP.md, padding: "10px 12px",
          background: T.bg, border: `1px solid ${T.b}`, borderRadius: 8,
          fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
          color: T.t2, whiteSpace: "pre-wrap", wordBreak: "break-all",
        }}>
          {`Swap initialized.\n\nSwap ID:    ${result.id}\nInvite blob:\n${result.invite_b64}\n\nNext: hand this invite to your counterparty (Signal, email, anything authenticated). Open the Handshake tab once they reply.`}
        </div>
      )}
    </Section>
  );
}

function RoleChip({ selected, onClick, title, subtitle }) {
  const T = useTheme();
  return (
    <button onClick={onClick} style={{
      flex: 1, padding: "12px 14px", textAlign: "left",
      background: selected ? `${T.ac2}12` : T.bg,
      border: `1px solid ${selected ? T.ac2 : T.b}`,
      borderRadius: 10, cursor: "pointer", transition: "all .15s",
    }}>
      <div style={{ fontSize: 12, fontWeight: 600, color: selected ? T.ac2 : T.t1 }}>{title}</div>
      <div style={{ fontSize: 10, color: T.t3, marginTop: 4 }}>{subtitle}</div>
    </button>
  );
}

// ── 2. Handshake ──────────────────────────────────────────────────────

function HandshakeForm({ push, backendOk }) {
  const T = useTheme();
  const [swapId, setSwapId] = useState("");
  const [peerInvite, setPeerInvite] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onHandshake() {
    if (!backendOk) return;
    if (!swapId.trim() || !peerInvite.trim()) {
      push("Swap ID + peer invite are required", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.swap.handshake({ swapId: swapId.trim(), peerInvite: peerInvite.trim() });
      setResult(r);
      push("Handshake complete — proceed to Lock", "success");
    } catch (e) {
      push(formatWalletError(e, "Handshake failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Exchange handshake material">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Paste your counterparty's invite blob. The wallet completes the Noise XX
        handshake, exchanges adaptor material + the cross-curve DLEQ proof, and
        produces a signed refund tx so neither side can be stranded.
      </div>

      <Input label="Swap ID" value={swapId} onChange={e => setSwapId(e.target.value)} mono
             placeholder="abc1234…" />
      <Lbl>Peer invite (paste exactly)</Lbl>
      <textarea value={peerInvite} onChange={e => setPeerInvite(e.target.value)} rows={6}
        placeholder="paste the counterparty's invite_b64 here"
        style={{
          width: "100%", padding: "10px 12px", marginBottom: SP.md,
          background: T.inputBg, border: `1px solid ${T.b}`, borderRadius: 8,
          fontSize: 11, color: T.t1, outline: "none",
          fontFamily: "'JetBrains Mono', monospace", resize: "vertical",
        }}/>

      <Btn onClick={onHandshake} disabled={!backendOk || loading}>
        {loading ? "Handshaking…" : "Run handshake"}
      </Btn>

      {result && (
        <div style={{
          marginTop: SP.md, padding: "10px 12px",
          background: T.bg, border: `1px solid ${T.b}`, borderRadius: 8,
          fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
          color: T.t2, whiteSpace: "pre-wrap", wordBreak: "break-all",
        }}>{JSON.stringify(result, null, 2)}</div>
      )}
    </Section>
  );
}

// ── 3. Lock ───────────────────────────────────────────────────────────

function LockForm({ push, backendOk }) {
  const T = useTheme();
  const [swapId, setSwapId] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onLock() {
    if (!backendOk) return;
    if (!swapId.trim()) {
      push("Swap ID is required", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.swap.lock({ swapId: swapId.trim() });
      setResult(r);
      push(`Lock broadcast — txid ${r.lock_txid?.slice(0, 16) || "(see output)"}…`, "success");
    } catch (e) {
      push(formatWalletError(e, "Lock failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Broadcast the lock transaction">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Bob broadcasts the BTC lock first. Alice broadcasts CYNC only after seeing
        N confirmations on the BTC lock — this prevents Bob from claiming both legs
        before Alice's CYNC is committed. The wallet polls for confirmations
        automatically; check the Active Swaps panel above for live state.
      </div>

      <Input label="Swap ID" value={swapId} onChange={e => setSwapId(e.target.value)} mono
             placeholder="abc1234…" />

      <Btn onClick={onLock} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Broadcasting…" : "Broadcast lock"}
      </Btn>

      {result && (
        <div style={{
          marginTop: SP.md, padding: "10px 12px",
          background: T.bg, border: `1px solid ${T.b}`, borderRadius: 8,
          fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
          color: T.t2, whiteSpace: "pre-wrap", wordBreak: "break-all",
        }}>{JSON.stringify(result, null, 2)}</div>
      )}
    </Section>
  );
}

// ── 4. Claim ──────────────────────────────────────────────────────────

function ClaimForm({ push, backendOk }) {
  const T = useTheme();
  const [swapId, setSwapId] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onClaim() {
    if (!backendOk) return;
    if (!swapId.trim()) {
      push("Swap ID is required", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.swap.claim({ swapId: swapId.trim() });
      setResult(r);
      push("Claim broadcast — swap completing", "success");
    } catch (e) {
      push(formatWalletError(e, "Claim failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Claim the counterparty's leg">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Alice claims BTC first; the claim signature reveals the adaptor secret.
        Bob's wallet watches the BTC claim, extracts the secret, and automatically
        spends the CYNC lock. <strong>The order is enforced cryptographically</strong> —
        Bob cannot claim CYNC before Alice has claimed BTC.
      </div>

      <Input label="Swap ID" value={swapId} onChange={e => setSwapId(e.target.value)} mono
             placeholder="abc1234…" />

      <Btn onClick={onClaim} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Broadcasting claim…" : "Claim"}
      </Btn>

      {result && (
        <div style={{
          marginTop: SP.md, padding: "10px 12px",
          background: T.bg, border: `1px solid ${T.b}`, borderRadius: 8,
          fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
          color: T.t2, whiteSpace: "pre-wrap", wordBreak: "break-all",
        }}>{JSON.stringify(result, null, 2)}</div>
      )}
    </Section>
  );
}

// ── 5. History ────────────────────────────────────────────────────────

function HistoryView({ push, backendOk }) {
  const T = useTheme();
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!backendOk) return;
    setLoading(true);
    rpc.swap.history()
      .then(r => setHistory(r?.swaps || []))
      .catch(() => setHistory([]))
      .finally(() => setLoading(false));
  }, [backendOk]);

  return (
    <Section title="Completed + refunded swaps">
      {loading && <div style={{ color: T.t3, fontSize: 11 }}>Loading…</div>}
      {!loading && history.length === 0 && (
        <div style={{ color: T.t3, fontSize: 11 }}>
          No swap history yet. Completed and refunded swaps will appear here.
        </div>
      )}
      {!loading && history.map(s => (
        <div key={s.id} style={{
          padding: "10px 12px", marginBottom: SP.sm,
          background: T.bg, border: `1px solid ${T.b}`, borderRadius: 8,
          fontSize: 11, color: T.t2,
        }}>
          <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
            <div style={{ fontFamily: "'JetBrains Mono', monospace", color: T.t1 }}>{s.id}</div>
            <StateChip state={s.state} />
          </div>
          <div style={{ color: T.t3 }}>
            {s.role} · {s.amount} · finalized {s.finalized_at || "—"}
          </div>
        </div>
      ))}
    </Section>
  );
}

function StateChip({ state }) {
  const T = useTheme();
  const color = state === "Completed" ? T.green : state === "Refunded" ? T.amber : T.t3;
  return (
    <span style={{
      padding: "2px 8px", borderRadius: 6, fontSize: 10,
      background: `${color}12`, color, border: `1px solid ${color}30`,
    }}>{state}</span>
  );
}
