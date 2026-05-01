import { useTheme, CoinLogo } from "./ui";

/** Shown when the React app runs in a browser tab instead of the Tauri desktop shell. */
export default function NonTauriPrompt() {
  const T = useTheme();
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "center", minHeight: "100vh", background: T.bg, padding: 24 }}>
      <div
        style={{
          maxWidth: 440,
          background: T.card,
          border: `1px solid ${T.b}`,
          borderRadius: 14,
          padding: "28px 32px",
          boxShadow: `0 20px 60px ${T.shadow}`,
        }}
      >
        <div style={{ marginBottom: 16, textAlign: "center" }}>
          <CoinLogo size={56} />
        </div>
        <h2 style={{ fontSize: 18, fontWeight: 700, marginBottom: 10, color: T.t1, textAlign: "center" }}>Desktop app required</h2>
        <p style={{ fontSize: 12, color: T.t2, lineHeight: 1.65, marginBottom: 14 }}>
          You opened the UI in a normal browser. CoinCync runs wallet logic in the{" "}
          <strong style={{ color: T.t1 }}>Tauri</strong> desktop shell, not in Chrome or Edge.
        </p>
        <p style={{ fontSize: 11, color: T.t3, lineHeight: 1.6, fontFamily: T.mono, marginBottom: 16 }}>
          From folder <code style={{ color: T.ac2 }}>coincync-wallet</code> run:
          <br />
          <code style={{ display: "block", marginTop: 8, color: T.t1 }}>npx tauri dev</code>
        </p>
        <p style={{ fontSize: 11, color: T.t3, lineHeight: 1.5, marginBottom: 14 }}>
          Use the <strong style={{ color: T.t1 }}>CoinCync Wallet</strong> window that opens — not{" "}
          <code style={{ color: T.t2 }}>http://localhost:1420</code>.
        </p>
      </div>
    </div>
  );
}
