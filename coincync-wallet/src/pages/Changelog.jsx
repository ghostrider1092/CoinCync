import { useState } from "react";
import { useTheme, Card, Badge, Ico, ICONS, Btn, CoinLogo, SP, RAD } from "../components/ui";

const RELEASES = [
  {
    version: "1.0.1",
    date: "April 19, 2026",
    title: "Network Hardening & Mempool Architecture",
    summary: "9-node testnet deployment with dedicated mempool nodes, sync optimizations, and consensus fixes.",
    breaking: false,
    categories: [
      {
        name: "Network",
        icon: ICONS.globe,
        items: [
          { type: "new", text: "3-seed bootstrap fleet across 3 continents: NJ (US-East), AMS (Europe), Tokyo (Asia-Pacific). Migrated from DigitalOcean to Vultr 2026-05-02." },
          { type: "new", text: "Dedicated mempool nodes for clean fee estimation and Dandelion++ observation" },
          { type: "improve", text: "Peer discovery: MAX_OUTBOUND 8→16, MAX_OUTBOUND_PER_SUBNET 2→4" },
          { type: "improve", text: "IBD sync 4x faster: 500ms tick, 5s base timeout, 2s/peer scaling" },
          { type: "new", text: "Hardcoded checkpoints at heights 10, 50, 100, 200, 300 for fast sync" },
        ]
      },
      {
        name: "Consensus",
        icon: ICONS.shield,
        items: [
          { type: "fix", text: "Miner fee burn now matches node validation (congestion-aware distribution)" },
          { type: "fix", text: "Clean workspace build with --features testnet prevents emission curve mismatch" },
          { type: "fix", text: "Block template includes correct coinbase after 30%/50% fee burn" },
        ]
      },
      {
        name: "Wallet",
        icon: ICONS.wallet,
        items: [
          { type: "fix", text: "Balance persists after scan instead of vanishing on refresh" },
          { type: "fix", text: "Seed phrase generation uses crypto.getRandomValues() instead of Math.random()" },
          { type: "fix", text: "Unlock screen verifies password via Tauri backend" },
          { type: "improve", text: "Receive page fetches real wallet address from RPC" },
          { type: "new", text: "Update notification system with changelog and progress screen" },
        ]
      },
      {
        name: "Explorer",
        icon: ICONS.globe,
        items: [
          { type: "new", text: "Node health dashboard queries the live seed fleet via nginx proxy" },
          { type: "fix", text: "IronConsensus metrics: Prometheus detection rejects HTML responses" },
          { type: "fix", text: "Network hashrate chart renders on first data point" },
          { type: "new", text: "Mempool page: sync button, auto-refresh, privacy feature badges per transaction" },
          { type: "new", text: "get_state_snapshot and get_blocks_batch RPCs for fast sync" },
        ]
      },
      {
        name: "UI/UX",
        icon: ICONS.settings,
        items: [
          { type: "new", text: "Design tokens: spacing, radius, shadow, timing scales" },
          { type: "new", text: "Reusable components: Toggle, Spinner, Skeleton, Modal, Select, EmptyState" },
          { type: "improve", text: "Settings split into 4 tabs: General, Privacy, Advanced, Security" },
          { type: "improve", text: "Animated page transitions with slide-in effect" },
          { type: "new", text: "CoinLogo uses explorer's coin image instead of SVG" },
          { type: "improve", text: "Notification stack limit (4), Escape dismiss, rate limiting" },
        ]
      },
    ]
  },
  {
    version: "1.0.0",
    date: "April 17, 2026",
    title: "Phantom Testnet Launch",
    summary: "Initial release of CoinCync — a privacy-first cryptocurrency with constitutional protections.",
    breaking: false,
    categories: [
      {
        name: "Privacy",
        icon: ICONS.shield,
        items: [
          { type: "new", text: "22 privacy features across 4 layers (Cryptographic, Network, Wallet, Constitutional)" },
          { type: "new", text: "CLSAG ring-11 signatures with uniform decoy selection" },
          { type: "new", text: "Bulletproofs+ range proofs on all outputs" },
          { type: "new", text: "Stealth one-time addresses (Ristretto255)" },
          { type: "new", text: "Dandelion++ transaction propagation with traffic shaping" },
          { type: "new", text: "Encrypted memos (ChaCha20Poly1305 + ECDH)" },
          { type: "new", text: "FROST threshold multi-sig (indistinguishable from single-sig)" },
        ]
      },
      {
        name: "Economics",
        icon: ICONS.mining,
        items: [
          { type: "new", text: "100M asymptotic supply cap with 0.6 CYNC tail emission" },
          { type: "new", text: "RandomX CPU-only mining (ASIC resistant)" },
          { type: "new", text: "30% fee burn (50% when congested), 0% dev tax" },
          { type: "new", text: "120-second block target with ASERT difficulty adjustment" },
        ]
      },
      {
        name: "Constitution",
        icon: ICONS.constitution,
        items: [
          { type: "new", text: "Article III: Mandatory privacy — no opt-out, no transparent mode" },
          { type: "new", text: "Article IX: No surveillance — no blacklists, no freezing" },
          { type: "new", text: "4th Amendment protection — financial records are constitutionally shielded" },
          { type: "new", text: "No balance lookup RPC exists by design" },
        ]
      },
    ]
  },
];

const TYPE_CONFIG = {
  new:      { label: "NEW",      color: "#d4a059", bg: "#d4a059" },
  fix:      { label: "FIX",      color: "#EF4444", bg: "#EF4444" },
  improve:  { label: "IMPROVED", color: "#F0C040", bg: "#F0C040" },
  security: { label: "SECURITY", color: "#6366F1", bg: "#6366F1" },
  breaking: { label: "BREAKING", color: "#EF4444", bg: "#EF4444" },
};

export default function Changelog() {
  const T = useTheme();
  const [expanded, setExpanded] = useState(RELEASES[0].version);

  return (
    <div style={{ animation: "fadeIn .2s ease" }}>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: SP.xxl }}>
        <div>
          <h1 style={{ fontFamily: T.serif, fontSize: 24, fontWeight: 400, marginBottom: 4 }}>What's New</h1>
          <p style={{ fontSize: 12, color: T.t3 }}>Release history and changelog for CoinCync Wallet</p>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: SP.md }}>
          <Badge label={`v${RELEASES[0].version}`} color={T.ac2} variant="solid" />
          <Badge label="Testnet" color={T.amber} />
        </div>
      </div>

      {RELEASES.map((release, ri) => {
        const isExpanded = expanded === release.version;
        const isCurrent = ri === 0;
        return (
          <div key={release.version} style={{ marginBottom: SP.xl }}>
            {/* Release header card */}
            <div
              onClick={() => setExpanded(isExpanded ? null : release.version)}
              style={{
                background: isCurrent
                  ? `linear-gradient(135deg, ${T.card}, ${T.ac2}08)`
                  : T.card,
                border: `1px solid ${isCurrent ? T.ac2 + "30" : T.b}`,
                borderRadius: isExpanded ? `${RAD.xl}px ${RAD.xl}px 0 0` : RAD.xl,
                padding: `${SP.xl + 4}px ${SP.xxl}px`,
                cursor: "pointer",
                transition: "all .15s",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
                <div style={{ display: "flex", alignItems: "center", gap: SP.lg }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: RAD.lg,
                    background: isCurrent ? `${T.ac2}15` : `${T.b}`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                  }}>
                    <span style={{ fontSize: 18, fontWeight: 700, color: isCurrent ? T.ac2 : T.t3, fontFamily: T.mono }}>
                      {release.version.split(".")[1]}
                    </span>
                  </div>
                  <div>
                    <div style={{ display: "flex", alignItems: "center", gap: SP.md }}>
                      <span style={{ fontSize: 16, fontWeight: 700 }}>v{release.version}</span>
                      {isCurrent && <Badge label="Latest" color={T.ac2} />}
                      {release.breaking && <Badge label="Breaking" color={T.red} />}
                    </div>
                    <div style={{ fontSize: 13, fontWeight: 500, color: T.t2, marginTop: 2 }}>{release.title}</div>
                    <div style={{ fontSize: 11, color: T.t3, marginTop: 2 }}>{release.date}</div>
                  </div>
                </div>
                <div style={{ display: "flex", alignItems: "center", gap: SP.lg }}>
                  <div style={{ textAlign: "right" }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: T.t2, fontFamily: T.mono }}>
                      {release.categories.reduce((sum, c) => sum + c.items.length, 0)}
                    </div>
                    <div style={{ fontSize: 9, color: T.t3, textTransform: "uppercase", letterSpacing: 1 }}>changes</div>
                  </div>
                  <Ico d={isExpanded ? "M18 15l-6-6-6 6" : "M6 9l6 6 6-6"} size={16} color={T.t3} />
                </div>
              </div>
              {!isExpanded && (
                <div style={{ fontSize: 11, color: T.t3, marginTop: SP.md, lineHeight: 1.5 }}>
                  {release.summary}
                </div>
              )}
            </div>

            {/* Expanded category cards */}
            {isExpanded && (
              <div style={{
                border: `1px solid ${isCurrent ? T.ac2 + "30" : T.b}`,
                borderTop: "none",
                borderRadius: `0 0 ${RAD.xl}px ${RAD.xl}px`,
                background: T.bg,
                padding: SP.xl,
              }}>
                <div style={{ fontSize: 11, color: T.t3, marginBottom: SP.xl, lineHeight: 1.5 }}>
                  {release.summary}
                </div>

                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: SP.lg }}>
                  {release.categories.map(cat => (
                    <div key={cat.name} style={{
                      background: T.card,
                      border: `1px solid ${T.b}`,
                      borderRadius: RAD.lg,
                      padding: `${SP.xl}px`,
                      display: "flex",
                      flexDirection: "column",
                    }}>
                      <div style={{ display: "flex", alignItems: "center", gap: SP.md, marginBottom: SP.lg }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: RAD.md,
                          background: `${T.ac2}10`,
                          display: "flex", alignItems: "center", justifyContent: "center",
                        }}>
                          <Ico d={cat.icon} size={14} color={T.ac2} />
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, letterSpacing: 0.3 }}>{cat.name}</span>
                        <span style={{ fontSize: 10, color: T.t3, marginLeft: "auto", fontFamily: T.mono }}>
                          {cat.items.length}
                        </span>
                      </div>

                      <div style={{ display: "flex", flexDirection: "column", gap: SP.md - 2 }}>
                        {cat.items.map((item, i) => {
                          const cfg = TYPE_CONFIG[item.type] || TYPE_CONFIG.new;
                          return (
                            <div key={i} style={{ display: "flex", alignItems: "flex-start", gap: SP.md }}>
                              <span style={{
                                background: `${cfg.bg}18`,
                                color: cfg.color,
                                fontSize: 8,
                                fontWeight: 700,
                                padding: "2px 5px",
                                borderRadius: 4,
                                letterSpacing: 0.5,
                                flexShrink: 0,
                                marginTop: 2,
                              }}>
                                {cfg.label}
                              </span>
                              <span style={{ fontSize: 11, color: T.t2, lineHeight: 1.4 }}>
                                {item.text}
                              </span>
                            </div>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Stats bar */}
                <div style={{
                  display: "flex", justifyContent: "center", gap: SP.xxl,
                  marginTop: SP.xl, padding: `${SP.lg}px 0`,
                  borderTop: `1px solid ${T.b}`,
                }}>
                  {Object.entries(
                    release.categories.flatMap(c => c.items).reduce((acc, item) => {
                      acc[item.type] = (acc[item.type] || 0) + 1;
                      return acc;
                    }, {})
                  ).map(([type, count]) => {
                    const cfg = TYPE_CONFIG[type] || TYPE_CONFIG.new;
                    return (
                      <div key={type} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                        <div style={{
                          width: 8, height: 8, borderRadius: "50%",
                          background: cfg.color,
                        }} />
                        <span style={{ fontSize: 11, color: T.t3 }}>
                          {count} {cfg.label.toLowerCase()}
                        </span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        );
      })}

      <div style={{ textAlign: "center", padding: `${SP.xxl}px 0`, fontFamily: T.serif, fontStyle: "italic", fontSize: 11, color: T.t3 }}>
        Private by law. Private by math.
      </div>
    </div>
  );
}
