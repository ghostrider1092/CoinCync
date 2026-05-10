import React, { useContext, useState } from "react";
import { ThemeCtx } from "../appContexts";

const TYPE_STYLE = {
  new:      { label: "NEW",      color: "#22D68C" },
  fix:      { label: "FIX",      color: "#EF4444" },
  improve:  { label: "IMPROVED", color: "#F0C040" },
  security: { label: "SECURITY", color: "#6366F1" },
};

function ChangeBadge({ type }) {
  const s = TYPE_STYLE[type] || { label: String(type || "").toUpperCase(), color: "#888" };
  return (
    <span style={{
      display: "inline-block",
      background: `${s.color}20`,
      color: s.color,
      fontSize: 9,
      fontWeight: 700,
      letterSpacing: 0.5,
      padding: "2px 7px",
      borderRadius: 4,
      flexShrink: 0,
      marginTop: 2,
      fontFamily: "monospace",
    }}>{s.label}</span>
  );
}

function fmtDate(iso) {
  if (!iso) return null;
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "long",
      day: "numeric",
    });
  } catch {
    return iso;
  }
}

async function openExternal(url) {
  if (!url) return;
  try {
    const { open } = await import("@tauri-apps/api/shell");
    await open(url);
  } catch {
    window.open(url, "_blank", "noopener");
  }
}

export default function UpdateBanner({ update }) {
  const T = useContext(ThemeCtx);
  const [expanded, setExpanded] = useState(false);

  if (!update.available) return null;

  const release = fmtDate(update.releaseDate);

  function handleUpdateNow() {
    openExternal(update.downloadUrl || update.releaseNotesUrl);
  }

  if (!expanded) {
    return (
      <div
        style={{
          position: "fixed",
          right: 24,
          bottom: 24,
          zIndex: 10000,
          background: T.card,
          border: `1px solid ${T.b}`,
          borderRadius: 14,
          boxShadow: `0 12px 40px ${T.shadow}, 0 0 0 1px ${T.ac}22`,
          padding: "14px 18px",
          minWidth: 320,
          maxWidth: 380,
          fontFamily: T.serif,
        }}
      >
        <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
          <div
            style={{
              width: 8,
              height: 8,
              borderRadius: "50%",
              background: T.ac2,
              boxShadow: `0 0 12px ${T.ac2}`,
              flexShrink: 0,
            }}
          />
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: 14, color: T.t1, fontWeight: 500 }}>
              Update available
            </div>
            <div style={{ fontSize: 11, color: T.t3, marginTop: 2 }}>
              v{update.latestVersion}{release ? ` · ${release}` : ""}
            </div>
          </div>
          <button
            onClick={() => setExpanded(true)}
            style={{
              fontFamily: "inherit",
              fontSize: 12,
              color: T.ac2,
              background: "transparent",
              border: "none",
              cursor: "pointer",
              padding: "4px 6px",
              textDecoration: "underline",
              textDecorationColor: `${T.ac2}55`,
              textUnderlineOffset: 3,
            }}
          >
            What's new?
          </button>
          <button
            onClick={handleUpdateNow}
            style={{
              fontFamily: "inherit",
              fontSize: 12,
              fontWeight: 600,
              color: "#1a1510",
              background: `linear-gradient(135deg, ${T.ac2}, ${T.ac})`,
              border: "none",
              borderRadius: 8,
              padding: "6px 12px",
              cursor: "pointer",
              whiteSpace: "nowrap",
            }}
          >
            Update Now
          </button>
          <button
            onClick={update.dismiss}
            aria-label="Dismiss"
            style={{
              fontFamily: "inherit",
              fontSize: 14,
              color: T.t3,
              background: "transparent",
              border: "none",
              cursor: "pointer",
              padding: "4px 6px",
              lineHeight: 1,
            }}
          >
            ×
          </button>
        </div>
      </div>
    );
  }

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.7)",
        backdropFilter: "blur(4px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 10000,
      }}
      onClick={() => setExpanded(false)}
    >
      <div
        onClick={(e) => e.stopPropagation()}
        style={{
          background: T.card,
          border: `1px solid ${T.b}`,
          borderRadius: 16,
          width: "min(520px, 90vw)",
          padding: "32px 32px 24px",
          boxShadow: `0 24px 80px rgba(0,0,0,0.6), 0 0 0 1px ${T.ac}22`,
          fontFamily: T.serif,
          position: "relative",
        }}
      >
        <button
          onClick={() => setExpanded(false)}
          aria-label="Close"
          style={{
            position: "absolute",
            top: 16,
            right: 16,
            fontFamily: "inherit",
            fontSize: 18,
            color: T.t3,
            background: "transparent",
            border: "none",
            cursor: "pointer",
            lineHeight: 1,
          }}
        >
          ×
        </button>
        <div style={{ fontSize: 12, color: T.ac2, fontFamily: "monospace", letterSpacing: 1, textTransform: "uppercase" }}>
          New release
        </div>
        <div style={{ fontSize: 28, fontWeight: 400, color: T.t1, marginTop: 6 }}>
          CoinCync Wallet v{update.latestVersion}
        </div>
        {release && (
          <div style={{ fontSize: 13, color: T.t2, marginTop: 4 }}>
            Released {release}
          </div>
        )}
        <div
          style={{
            marginTop: 22,
            padding: "14px 16px",
            background: T.bg,
            border: `1px solid ${T.b}`,
            borderRadius: 10,
            maxHeight: 280,
            overflowY: "auto",
          }}
        >
          {update.releases && update.releases.length > 0 ? (
            update.releases.map((rel, ri) => (
              <div key={rel.version || ri} style={{ marginBottom: ri === update.releases.length - 1 ? 0 : 18 }}>
                <div style={{
                  display: "flex", alignItems: "center", gap: 8,
                  marginBottom: 8, paddingBottom: 6,
                  borderBottom: `1px solid ${T.b}`,
                }}>
                  <span style={{ fontSize: 13, fontWeight: 600, color: T.t1 }}>v{rel.version}</span>
                  {rel.date && (
                    <span style={{ fontSize: 10, color: T.t3, fontFamily: "monospace" }}>
                      {fmtDate(rel.date) || rel.date}
                    </span>
                  )}
                </div>
                {(rel.changes || []).map((c, ci) => (
                  <div key={ci} style={{
                    display: "flex", alignItems: "flex-start", gap: 8,
                    padding: "4px 0", fontSize: 12, color: T.t2, lineHeight: 1.5,
                  }}>
                    <ChangeBadge type={c.type}/>
                    <span style={{ flex: 1 }}>{c.text}</span>
                  </div>
                ))}
              </div>
            ))
          ) : (
            <div style={{
              fontSize: 13, color: T.t2, lineHeight: 1.6, whiteSpace: "pre-line",
            }}>
              {update.notes ||
                "Bug fixes and improvements. Click 'View release notes' for the full changelog."}
            </div>
          )}
        </div>
        {update.releaseNotesUrl && (
          <button
            onClick={() => openExternal(update.releaseNotesUrl)}
            style={{
              fontFamily: "inherit",
              fontSize: 12,
              color: T.ac2,
              background: "transparent",
              border: "none",
              cursor: "pointer",
              padding: "8px 0 0",
              textDecoration: "underline",
              textDecorationColor: `${T.ac2}55`,
              textUnderlineOffset: 3,
            }}
          >
            View full release notes ↗
          </button>
        )}
        <div
          style={{
            display: "flex",
            gap: 10,
            marginTop: 24,
            justifyContent: "flex-end",
          }}
        >
          <button
            onClick={update.dismiss}
            style={{
              fontFamily: "inherit",
              fontSize: 13,
              color: T.t2,
              background: "transparent",
              border: `1px solid ${T.b}`,
              borderRadius: 8,
              padding: "10px 18px",
              cursor: "pointer",
            }}
          >
            Later
          </button>
          <button
            onClick={handleUpdateNow}
            style={{
              fontFamily: "inherit",
              fontSize: 13,
              fontWeight: 600,
              color: "#1a1510",
              background: `linear-gradient(135deg, ${T.ac2}, ${T.ac})`,
              border: "none",
              borderRadius: 8,
              padding: "10px 22px",
              cursor: "pointer",
            }}
          >
            Update Now
          </button>
        </div>
        <div
          style={{
            fontSize: 10,
            color: T.t3,
            fontStyle: "italic",
            marginTop: 18,
            textAlign: "center",
            letterSpacing: 0.5,
          }}
        >
          Private by law. Private by math.
        </div>
      </div>
    </div>
  );
}
