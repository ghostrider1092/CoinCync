import React, { useState, useContext } from "react";
import { useTheme, Card, Btn, Ico, Lbl, Input, Section, ICONS, SP } from "../components/ui";
import { rpc, isWalletBackendAvailable, formatWalletError } from "../utils/rpc";
import { NotifCtx } from "../appContexts";

// ── Multi-sig (FROST M-of-N) ──────────────────────────────────────────
//
// File-based flow today. The wallet CLI does the FROST cryptography;
// this page shuttles JSON file paths between participants via the
// 6-stage CIP-008 protocol:
//
//   1. Generate    — one operator creates N key shares, distributes
//                    them to participants
//   2. Share Info  — any participant inspects their share metadata
//   3. Round 1     — each signer generates a commitment + secret nonce
//   4. Round 2     — each signer combines commitments + message + their
//                    share + their nonce → a signature share
//   5. Aggregate   — combine M signature shares into the final signature
//   6. Send        — submit a tx using the aggregate (or, for single-
//                    operator testing, hand all M shares at once)
//
// The coord-relayed variant (wss://api.coincync.network/coord/) will
// automate steps 3-5 by relaying files between participants. The file-
// based flow stays as the offline/fallback path.

const TABS = [
  { id: "gen",       label: "1. Generate",   short: "Gen" },
  { id: "info",      label: "2. Share Info", short: "Info" },
  { id: "round1",    label: "3. Round 1",    short: "R1" },
  { id: "round2",    label: "4. Round 2",    short: "R2" },
  { id: "aggregate", label: "5. Aggregate",  short: "Agg" },
  { id: "send",      label: "6. Send",       short: "Send" },
];

export default function Multisig() {
  const T = useTheme();
  const { push } = useContext(NotifCtx);
  const [tab, setTab] = useState("gen");

  const backendOk = isWalletBackendAvailable();

  return (
    <div style={{ animation: "fadeIn .2s ease", maxWidth: "100%" }}>
      {/* Header */}
      <div style={{ marginBottom: SP.lg }}>
        <h1 style={{ fontSize: 21, fontWeight: 700 }}>Multi-sig (FROST)</h1>
        <div style={{ fontSize: 11, color: T.t3, marginTop: 4 }}>
          M-of-N threshold signing per <code>CIP-008</code>. File-based flow today; coord-relayed automation lands in a later release.
        </div>
      </div>

      {/* Backend availability banner */}
      {!backendOk && (
        <div style={{
          padding: "12px 16px", marginBottom: 14,
          background: `${T.amber}12`, border: `1px solid ${T.amber}30`,
          borderRadius: 10, fontSize: 12, color: T.amber,
        }}>
          Multi-sig actions require the desktop Tauri backend. Open this app via <code>npx tauri dev</code> or the installer build — browser tabs can&rsquo;t shell out to the wallet CLI.
        </div>
      )}

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
      {tab === "gen"       && <GenForm       push={push} backendOk={backendOk} />}
      {tab === "info"      && <InfoForm      push={push} backendOk={backendOk} />}
      {tab === "round1"    && <Round1Form    push={push} backendOk={backendOk} />}
      {tab === "round2"    && <Round2Form    push={push} backendOk={backendOk} />}
      {tab === "aggregate" && <AggregateForm push={push} backendOk={backendOk} />}
      {tab === "send"      && <SendForm      push={push} backendOk={backendOk} />}

      {/* Footer note about coord */}
      <div style={{
        marginTop: SP.xxl, padding: "12px 16px",
        background: `${T.ac2}06`, borderLeft: `3px solid ${T.ac2}`,
        borderRadius: "0 8px 8px 0", fontSize: 11, color: T.t2, lineHeight: 1.6,
      }}>
        <strong style={{ color: T.ac2 }}>Coming later:</strong> a coord-relayed mode that automates steps 3&ndash;5 via <code>wss://api.coincync.network/coord/</code>, so participants don&rsquo;t hand-shuffle JSON files. CIP-008 phase 5/6 work.
      </div>
    </div>
  );
}

// ── Helpers ───────────────────────────────────────────────────────────

function splitPaths(text) {
  return (text || "").split(/[\r\n]+/).map(s => s.trim()).filter(Boolean);
}

function ResultBox({ children, T }) {
  if (!children) return null;
  return (
    <div style={{
      marginTop: SP.md, padding: "10px 12px",
      background: T.bg, border: `1px solid ${T.b}`, borderRadius: 8,
      fontFamily: "'JetBrains Mono', monospace", fontSize: 11,
      color: T.t2, whiteSpace: "pre-wrap", wordBreak: "break-all",
    }}>{children}</div>
  );
}

function MultiPathInput({ label, value, onChange, hint, T }) {
  return (
    <div style={{ marginBottom: SP.lg }}>
      <Lbl>{label}</Lbl>
      <textarea value={value} onChange={e => onChange(e.target.value)}
        rows={4} placeholder="one path per line"
        style={{
          width: "100%", padding: "10px 12px",
          background: T.inputBg, border: `1px solid ${T.b}`,
          borderRadius: 8, fontSize: 11, color: T.t1, outline: "none",
          fontFamily: "'JetBrains Mono', monospace", resize: "vertical",
        }}/>
      {hint && <div style={{ fontSize: 10, color: T.t3, marginTop: 4 }}>{hint}</div>}
    </div>
  );
}

// ── 1. Generate ───────────────────────────────────────────────────────

function GenForm({ push, backendOk }) {
  const T = useTheme();
  const [threshold, setThreshold] = useState("2");
  const [total, setTotal] = useState("3");
  const [outputDir, setOutputDir] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onGenerate() {
    if (!backendOk) return;
    const t = parseInt(threshold, 10);
    const n = parseInt(total, 10);
    if (!(t >= 1 && n >= t && n <= 256)) {
      push("Threshold must be 1..N; total must be 1..256", "warning");
      return;
    }
    if (!outputDir.trim()) {
      push("Output directory is required", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.multisig.gen({ threshold: t, total: n, outputDir: outputDir.trim() });
      setResult(r);
      push(`Generated ${r.share_files.length} share files`, "success");
    } catch (e) {
      push(formatWalletError(e, "Generation failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Generate M-of-N Key Shares">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Produces <strong>N</strong> key share files. Distribute one to each participant via a secure channel. Any <strong>M</strong> of them can later collaborate to sign a transaction; fewer than M cannot. Lose more than (N&minus;M) shares and the wallet becomes permanently unspendable &mdash; back them up.
      </div>
      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10, marginBottom: 10 }}>
        <Input label="Threshold (M)"    type="number" value={threshold} onChange={e=>setThreshold(e.target.value)} mono hint="Minimum signers required"/>
        <Input label="Total (N)"        type="number" value={total}     onChange={e=>setTotal(e.target.value)}     mono hint="Participants"/>
      </div>
      <Input label="Output directory" value={outputDir} onChange={e=>setOutputDir(e.target.value)} mono
             placeholder="e.g. C:\Users\you\multisig-session-1\"
             hint="Absolute path. Will be created if missing."/>
      <Btn onClick={onGenerate} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Generating..." : `Generate ${threshold}-of-${total}`}
      </Btn>
      {result && (
        <ResultBox T={T}>
          {`Generated ${result.share_files.length} share files in:\n${result.output_dir}\n\n` +
            result.share_files.map((f, i) => `  ${i + 1}. ${f}`).join("\n") +
            `\n\nNext: distribute one file to each participant. They can inspect their share via the "Share Info" tab.`}
        </ResultBox>
      )}
    </Section>
  );
}

// ── 2. Share Info ─────────────────────────────────────────────────────

function InfoForm({ push, backendOk }) {
  const T = useTheme();
  const [shareFile, setShareFile] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onInspect() {
    if (!backendOk || !shareFile.trim()) return;
    setLoading(true);
    try {
      const r = await rpc.multisig.info({ shareFile: shareFile.trim() });
      setResult(r.info);
    } catch (e) {
      push(formatWalletError(e, "Inspect failed"), "warning");
      setResult(null);
    }
    setLoading(false);
  }

  return (
    <Section title="Inspect a Key Share">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14 }}>
        Read-only. Shows the share&rsquo;s identifier, threshold/total, and the wallet&rsquo;s group public key &mdash; useful for verifying you have the right file before round 1.
      </div>
      <Input label="Share file" value={shareFile} onChange={e=>setShareFile(e.target.value)} mono
             placeholder="path/to/share-N.json"/>
      <Btn onClick={onInspect} disabled={!backendOk || loading || !shareFile.trim()} style={{ marginTop: SP.md }}>
        {loading ? "Reading..." : "Inspect"}
      </Btn>
      <ResultBox T={T}>{result}</ResultBox>
    </Section>
  );
}

// ── 3. Round 1 ────────────────────────────────────────────────────────

function Round1Form({ push, backendOk }) {
  const T = useTheme();
  const [shareFile, setShareFile] = useState("");
  const [output, setOutput] = useState("round1-commitment.json");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onRun() {
    if (!backendOk || !shareFile.trim() || !output.trim()) return;
    setLoading(true);
    try {
      const r = await rpc.multisig.round1({ shareFile: shareFile.trim(), output: output.trim() });
      setResult(r);
      push("Round 1 commitment generated", "success");
    } catch (e) {
      push(formatWalletError(e, "Round 1 failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Round 1 — Generate Commitment + Nonce">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Each signer runs this once per signing session. Produces two files: a <strong>commitment</strong> (share with the other participants) and a <strong>secret nonce</strong> (keep private &mdash; you&rsquo;ll need it for round 2; never reuse it).
      </div>
      <Input label="Your key share file" value={shareFile} onChange={e=>setShareFile(e.target.value)} mono
             placeholder="path/to/share-N.json"/>
      <Input label="Commitment output path" value={output} onChange={e=>setOutput(e.target.value)} mono
             hint="The CLI writes a secondary `.nonce` file alongside this — do not share."/>
      <Btn onClick={onRun} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Generating..." : "Generate commitment"}
      </Btn>
      {result && (
        <ResultBox T={T}>
          {`Commitment file (share with other signers):\n  ${result.commitment_file}\n\n` +
           `Nonce file (KEEP PRIVATE — required for round 2):\n  ${result.nonce_file}`}
        </ResultBox>
      )}
    </Section>
  );
}

// ── 4. Round 2 ────────────────────────────────────────────────────────

function Round2Form({ push, backendOk }) {
  const T = useTheme();
  const [shareFile, setShareFile] = useState("");
  const [nonceFile, setNonceFile] = useState("");
  const [commitments, setCommitments] = useState("");
  const [message, setMessage] = useState("");
  const [output, setOutput] = useState("round2-share.json");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onRun() {
    if (!backendOk) return;
    const cmts = splitPaths(commitments);
    if (!shareFile.trim() || !nonceFile.trim() || !message.trim() || !output.trim() || cmts.length === 0) {
      push("All fields are required + at least one commitment path", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.multisig.round2({
        shareFile: shareFile.trim(),
        nonceFile: nonceFile.trim(),
        commitments: cmts,
        message: message.trim(),
        output: output.trim(),
      });
      setResult(r);
      push("Signature share produced", "success");
    } catch (e) {
      push(formatWalletError(e, "Round 2 failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Round 2 — Produce Signature Share">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Combine your share, your secret nonce from round 1, the message being signed, and all participants&rsquo; round-1 commitments into a single signature share. Distribute the output to whoever runs the <strong>Aggregate</strong> step.
      </div>
      <Input label="Your key share file" value={shareFile} onChange={e=>setShareFile(e.target.value)} mono/>
      <Input label="Your secret nonce file (from round 1)" value={nonceFile} onChange={e=>setNonceFile(e.target.value)} mono/>
      <MultiPathInput label="All participants' commitment files (one path per line)"
                      value={commitments} onChange={setCommitments} T={T}
                      hint="Include your own commitment too. Must total M paths for an M-of-N signing."/>
      <Input label="Message to sign (hex)" value={message} onChange={e=>setMessage(e.target.value)} mono
             placeholder="64-hex transaction hash, or any hex-encoded message"/>
      <Input label="Signature share output path" value={output} onChange={e=>setOutput(e.target.value)} mono/>
      <Btn onClick={onRun} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Signing..." : "Produce signature share"}
      </Btn>
      {result && (
        <ResultBox T={T}>
          {`Signature share written:\n  ${result.sig_share_file}\n\n` +
           `Hand this to the aggregator along with your commitment.`}
        </ResultBox>
      )}
    </Section>
  );
}

// ── 5. Aggregate ──────────────────────────────────────────────────────

function AggregateForm({ push, backendOk }) {
  const T = useTheme();
  const [commitments, setCommitments] = useState("");
  const [shares, setShares] = useState("");
  const [keyShares, setKeyShares] = useState("");
  const [message, setMessage] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onRun() {
    if (!backendOk) return;
    const cmts = splitPaths(commitments);
    const shs  = splitPaths(shares);
    const kss  = splitPaths(keyShares);
    if (cmts.length === 0 || shs.length === 0 || kss.length === 0 || !message.trim()) {
      push("All fields are required", "warning");
      return;
    }
    if (cmts.length !== shs.length) {
      push("Commitments and signature shares must have the same count", "warning");
      return;
    }
    setLoading(true);
    try {
      const r = await rpc.multisig.aggregate({
        commitments: cmts,
        shares: shs,
        keyShares: kss,
        message: message.trim(),
      });
      setResult(r);
      if (r.signature_hex) {
        push("Aggregate signature produced", "success");
      } else {
        push("Aggregation succeeded but no signature parsed — check raw output", "info");
      }
    } catch (e) {
      push(formatWalletError(e, "Aggregate failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Aggregate Signature Shares">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Combine M signature shares into the final aggregate signature. The aggregator doesn&rsquo;t need to hold a key share themselves &mdash; only the JSON files. Output is a hex signature ready to attach to the transaction.
      </div>
      <MultiPathInput label="Commitment files (M paths, one per line)"
                      value={commitments} onChange={setCommitments} T={T}/>
      <MultiPathInput label="Signature share files (M paths, one per line)"
                      value={shares} onChange={setShares} T={T}/>
      <MultiPathInput label="Key share files (M paths, one per line)"
                      value={keyShares} onChange={setKeyShares} T={T}
                      hint="Used to verify the group public key matches."/>
      <Input label="Message that was signed (hex)" value={message} onChange={e=>setMessage(e.target.value)} mono/>
      <Btn onClick={onRun} disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Aggregating..." : "Aggregate"}
      </Btn>
      {result && (
        <ResultBox T={T}>
          {(result.signature_hex ? `Signature (hex):\n  ${result.signature_hex}\n\n` : "") +
           `Raw CLI output:\n${result.raw}`}
        </ResultBox>
      )}
    </Section>
  );
}

// ── 6. Send ───────────────────────────────────────────────────────────

function SendForm({ push, backendOk }) {
  const T = useTheme();
  const [keyShares, setKeyShares] = useState("");
  const [toSpend, setToSpend] = useState("");
  const [toView, setToView] = useState("");
  const [amount, setAmount] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);

  async function onSend() {
    if (!backendOk) return;
    const ks = splitPaths(keyShares);
    const amtCync = parseFloat(amount);
    if (ks.length === 0 || !toSpend.trim() || !toView.trim() || !(amtCync > 0)) {
      push("All fields are required + amount > 0", "warning");
      return;
    }
    if (toSpend.trim().length !== 64 || toView.trim().length !== 64) {
      push("Spend + view keys must each be 64 hex chars", "warning");
      return;
    }
    if (!window.confirm(`Send ${amtCync} CYNC to ${toSpend.trim().slice(0,16)}… using ${ks.length} key shares?\n\nThis builds a real privacy tx and submits to the node.`)) {
      return;
    }
    setLoading(true);
    try {
      const amount_atomic = Math.round(amtCync * 1e12);
      const r = await rpc.multisig.send({
        keyShares: ks,
        toSpend: toSpend.trim(),
        toView: toView.trim(),
        amount: amount_atomic,
      });
      setResult(r);
      push(`Tx ${r.status}: ${r.txid.slice(0, 16)}…`, "success");
    } catch (e) {
      push(formatWalletError(e, "Send failed"), "warning");
    }
    setLoading(false);
  }

  return (
    <Section title="Send via Multi-Sig">
      <div style={{ fontSize: 11, color: T.t3, marginBottom: 14, lineHeight: 1.6 }}>
        Single-operator path: build + sign + submit in one go, using all M shares at once. Useful for testing the crypto end-to-end. For real multi-party signing where each participant holds only their own share, use the Round 1 &rarr; Round 2 &rarr; Aggregate flow above, then attach the resulting signature to a tx via the regular Send page.
      </div>
      <div style={{ padding: "10px 12px", marginBottom: 14,
        background: `${T.amber}09`, border: `1px solid ${T.amber}20`,
        borderRadius: 7, fontSize: 11, color: T.amber }}>
        <strong>Note:</strong> Holding all M shares yourself defeats the security purpose of M-of-N. This screen is for testing the crypto and for single-operator wallets only.
      </div>
      <MultiPathInput label="Key share files (M paths, one per line)"
                      value={keyShares} onChange={setKeyShares} T={T}
                      hint="Each line = one key-share JSON file produced by Generate."/>
      <Input label="Recipient spend pubkey (64-hex)" value={toSpend} onChange={e=>setToSpend(e.target.value)} mono/>
      <Input label="Recipient view pubkey (64-hex)" value={toView} onChange={e=>setToView(e.target.value)} mono/>
      <Input label="Amount (CYNC)" type="number" value={amount} onChange={e=>setAmount(e.target.value)} mono
             placeholder="e.g. 1.5"/>
      <Btn onClick={onSend} variant="danger" disabled={!backendOk || loading} style={{ marginTop: SP.md }}>
        {loading ? "Submitting..." : "Build + sign + submit"}
      </Btn>
      {result && (
        <ResultBox T={T}>
          {`Status: ${result.status}\nTxid:   ${result.txid}`}
        </ResultBox>
      )}
    </Section>
  );
}
