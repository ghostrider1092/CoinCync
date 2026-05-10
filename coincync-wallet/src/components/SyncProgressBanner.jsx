import { useEffect, useRef, useState } from "react";
import { useTheme, Ico, ICONS } from "./ui";

const SAMPLE_WINDOW = 6;
const HIDDEN_THRESHOLD_PCT = 99.9;

function fmtEta(secs) {
  if (!secs || !Number.isFinite(secs) || secs <= 0) return null;
  if (secs < 60) return "<1 min";
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} min`;
  const hours = Math.floor(mins / 60);
  const rem = mins % 60;
  return rem ? `${hours}h ${rem}m` : `${hours}h`;
}

export default function SyncProgressBanner({ syncInfo }) {
  const T = useTheme();
  const samplesRef = useRef([]);
  const [eta, setEta] = useState(null);

  useEffect(() => {
    if (!syncInfo || syncInfo.height == null) return;
    const now = Date.now();
    samplesRef.current.push({ t: now, h: syncInfo.height });
    if (samplesRef.current.length > SAMPLE_WINDOW) {
      samplesRef.current.shift();
    }
    if (samplesRef.current.length >= 2) {
      const first = samplesRef.current[0];
      const last = samplesRef.current[samplesRef.current.length - 1];
      const dh = last.h - first.h;
      const dt = (last.t - first.t) / 1000;
      const target = syncInfo.chainHeight || 0;
      const remaining = target - last.h;
      if (dh > 0 && dt > 0 && remaining > 0) {
        setEta(Math.round(remaining / (dh / dt)));
      } else {
        setEta(null);
      }
    }
  }, [syncInfo]);

  if (!syncInfo) return null;
  const pct = Number(syncInfo.syncPct || 0);
  if (pct >= HIDDEN_THRESHOLD_PCT) return null;

  const height = syncInfo.height || 0;
  const target = syncInfo.chainHeight || 0;
  const etaText = fmtEta(eta);

  return (
    <div style={{
      marginBottom: 20,
      padding: "16px 20px",
      background: `linear-gradient(135deg, ${T.ac2}10, ${T.ac2}04)`,
      border: `1px solid ${T.ac2}25`,
      borderRadius: 12,
      display: "flex",
      flexDirection: "column",
      gap: 12,
    }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
        <div style={{
          width: 28, height: 28, borderRadius: 8,
          background: `${T.ac2}18`,
          display: "flex", alignItems: "center", justifyContent: "center",
          flexShrink: 0,
        }}>
          <Ico d={ICONS.history || "M12 8v4l3 3"} size={14} color={T.ac2} />
        </div>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{
            fontFamily: T.serif, fontSize: 14, color: T.t1, fontWeight: 500,
          }}>
            Syncing testnet
          </div>
          <div style={{
            fontFamily: T.mono, fontSize: 11, color: T.t2, marginTop: 2,
          }}>
            block {height.toLocaleString()} of {target.toLocaleString() || "—"} · {pct.toFixed(1)}%
            {etaText && <span style={{ color: T.t3 }}> · ~{etaText} remaining</span>}
          </div>
        </div>
        <div style={{
          fontFamily: T.mono, fontSize: 18, fontWeight: 600,
          color: T.ac2, whiteSpace: "nowrap",
        }}>
          {Math.floor(pct)}%
        </div>
      </div>

      <div style={{
        height: 6, background: `${T.b}80`, borderRadius: 3, overflow: "hidden",
      }}>
        <div style={{
          height: "100%",
          width: `${Math.min(Math.max(pct, 0), 100)}%`,
          background: `linear-gradient(90deg, ${T.ac2}, ${T.ac})`,
          borderRadius: 3,
          transition: "width 1s ease",
          boxShadow: `0 0 8px ${T.ac2}60`,
        }} />
      </div>

      <div style={{
        fontSize: 10, color: T.t3, fontStyle: "italic", fontFamily: T.serif,
      }}>
        Your wallet is downloading the testnet chain from peers. This is normal on first launch.
        You can browse the wallet during sync — send and receive will be available once it completes.
      </div>
    </div>
  );
}
