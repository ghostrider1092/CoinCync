import React, { useState, useEffect, useCallback, useRef } from "react";
import { THEMES, DARK, LIGHT, applyTheme, applyWallpaper } from "./utils/theme";
import { loadTheme, saveTheme, isWalletCreated, isSeedBackedUp, loadSettings } from "./utils/storage";
import { useWallet } from "./hooks/useWallet";
import { useNotifications } from "./hooks/useNotifications";
import Sidebar from "./components/Sidebar";
import Notifications from "./components/Notifications";
import Onboarding from "./components/Onboarding";
import WalletSetup from "./pages/WalletSetup";
import Unlock from "./pages/Unlock";
import Dashboard from "./pages/Dashboard";
import Send from "./pages/Send";
import Receive from "./pages/Receive";
import History from "./pages/History";
import Addresses from "./pages/Addresses";
import Mining from "./pages/Mining";
import Keys from "./pages/Keys";
import Constitution from "./pages/Compliance";
import Privacy from "./pages/Privacy";
import Settings from "./pages/Settings";
import About from "./pages/About";
import Changelog from "./pages/Changelog";
import Audit from "./pages/Audit";
import SplashScreen from "./components/SplashScreen";
import ErrorBoundary from "./components/ErrorBoundary";
import { ThemeCtx, WalletCtx, NotifCtx, NavCtx } from "./appContexts";
import { rpc, isWalletBackendAvailable } from "./utils/rpc";

window.React = React;

const PAGES = {
  dashboard:Dashboard, send:Send, receive:Receive, history:History,
  addresses:Addresses, mining:Mining, keys:Keys, constitution:Constitution,
  privacy:Privacy, audit:Audit, settings:Settings, changelog:Changelog, about:About,
};

// ── Disclaimer ────────────────────────────────────────────────────────
function Disclaimer({ onAccept, T }) {
  return (
    <div style={{ position:"fixed", inset:0, background:"rgba(0,0,0,0.85)",
      display:"flex", alignItems:"center", justifyContent:"center", zIndex:9999 }}>
      <div style={{ background:T.card, border:`1px solid ${T.b}`, borderRadius:16,
        maxWidth:520, width:"90%", padding:"32px 28px", boxShadow:`0 8px 40px rgba(0,0,0,.5)` }}>
        <div style={{ textAlign:"center", marginBottom:20 }}>
          <div style={{ fontSize:32, marginBottom:8 }}>&#9888;</div>
          <div style={{ fontFamily:T.serif, fontSize:22, fontWeight:400 }}>Important Notice</div>
        </div>
        <div style={{ fontSize:12, color:T.t2, lineHeight:1.7, marginBottom:20 }}>
          <p style={{ marginBottom:10 }}><strong style={{ color:T.t1 }}>Testnet software.</strong> Coins have no real value.</p>
          <p style={{ marginBottom:10 }}><strong style={{ color:T.t1 }}>Your keys, your responsibility.</strong> Lose your seed = lose your coins.</p>
          <p style={{ marginBottom:10 }}><strong style={{ color:T.t1 }}>Privacy is mandatory.</strong> No transparent mode.</p>
          <p><strong style={{ color:T.t1 }}>No warranty.</strong> Use at your own risk.</p>
        </div>
        <div style={{ padding:"12px 16px", background:`${T.ac2}08`, borderLeft:`3px solid ${T.ac2}`,
          borderRadius:"0 8px 8px 0", fontSize:11, color:T.t2, lineHeight:1.6, marginBottom:20, fontStyle:"italic" }}>
          "The right of the people to be secure in their persons, houses, papers, and effects..."
          <div style={{ fontSize:9, color:T.t3, marginTop:4, fontStyle:"normal", fontFamily:"monospace" }}>— Fourth Amendment, 1791</div>
        </div>
        <button onClick={onAccept} style={{ width:"100%", padding:"12px", borderRadius:10, border:"none",
          background:`linear-gradient(135deg, ${T.ac2}, ${T.ac})`, color:"#fff", fontSize:14, fontWeight:700, cursor:"pointer" }}>
          I Understand — Continue
        </button>
      </div>
    </div>
  );
}

// ── Testnet Banner ────────────────────────────────────────────────────
function TestnetBanner() {
  return (
    <div style={{ background:"#92400E", color:"#FEF3C7", fontSize:10, fontWeight:600,
      textAlign:"center", padding:"3px 0", fontFamily:"monospace", letterSpacing:.5, zIndex:20 }}>
      TESTNET — coins have no real value · Ctrl+L lock · Ctrl+S send · Ctrl+R receive · Ctrl+M mine
    </div>
  );
}

// ── Main App ──────────────────────────────────────────────────────────
export default function App() {
  const [themeName, setThemeName] = useState(() => localStorage.getItem("cc_theme") || "dark");
  const T = THEMES[themeName] || DARK;
  const [showSplash, setShowSplash] = useState(true);

  const [appState, setAppState] = useState(() => {
    if (!localStorage.getItem("cc_disclaimer_accepted")) return "disclaimer";
    if (!localStorage.getItem("cc_onboarding_done")) return "onboarding";
    if (!isWalletCreated()) return "setup";
    return "locked";
  });
  const [page, setPage] = useState("dashboard");
  const [transitionKey, setTransitionKey] = useState("dashboard");
  const [transitioning, setTransitioning] = useState(false);

  const wallet = useWallet();
  const notifs = useNotifications();
  const currentSettings = loadSettings();
  const autoLockMinutes = Number(currentSettings.autoLockMinutes ?? 15);
  const lockWalletUi = useCallback(async (message) => {
    if (isWalletBackendAvailable()) {
      try {
        await rpc.lockWallet();
      } catch {
        // UI lock still applies even if backend call fails.
      }
    }
    setAppState("locked");
    if (message) notifs.push(message, "info");
  }, [notifs]);

  const navigateTo = useCallback((newPage) => {
    if (newPage === page) return;
    setTransitioning(true);
    setTimeout(() => {
      setPage(newPage);
      setTransitionKey(newPage);
      setTransitioning(false);
    }, 120);
  }, [page]);

  // Auto-lock after inactivity timeout
  const [lastActivity, setLastActivity] = useState(Date.now());
  useEffect(() => {
    const reset = () => setLastActivity(Date.now());
    window.addEventListener("mousemove", reset);
    window.addEventListener("keydown", reset);
    const checker = setInterval(() => {
      const settings = loadSettings();
      const autoLockMinutes = Number(settings.autoLockMinutes ?? 15);
      if (!Number.isFinite(autoLockMinutes) || autoLockMinutes <= 0) return;
      const autoLockMs = autoLockMinutes * 60 * 1000;
      if (appState === "unlocked" && Date.now() - lastActivity > autoLockMs) {
        lockWalletUi(`Wallet locked (${autoLockMinutes} min inactivity)`);
      }
    }, 30000);
    return () => { window.removeEventListener("mousemove", reset); window.removeEventListener("keydown", reset); clearInterval(checker); };
  }, [appState, lastActivity, lockWalletUi]);

  // Keyboard shortcuts
  useEffect(() => {
    const handler = (e) => {
      if (appState !== "unlocked") return;
      if (e.ctrlKey || e.metaKey) {
        const map = { s:"send", r:"receive", m:"mining", d:"dashboard", h:"history" };
        if (map[e.key]) { e.preventDefault(); navigateTo(map[e.key]); }
        if (e.key === "l") { e.preventDefault(); lockWalletUi("Wallet locked"); }
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [appState, navigateTo, lockWalletUi]);

  useEffect(() => { applyTheme(T); }, [T]);

  // Auto-scan on unlock
  useEffect(() => {
    if (appState === "unlocked") {
      setTimeout(() => wallet.scanWallet(), 1500);
    }
  }, [appState]);

  // Startup update-check — Monero posture: only runs when the user has
  // explicitly opted in via Settings → Updates → "Check for updates on
  // startup" (default OFF). Fires once per app session, after first
  // unlock so Notifications is mounted. Errors are silent — a wallet
  // launch should not raise a popup just because GitHub blipped.
  const updateChecked = useRef(false);
  useEffect(() => {
    if (updateChecked.current) return;
    if (appState !== "unlocked") return;
    if (!isWalletBackendAvailable()) return;
    if (!loadSettings().checkUpdates) return;
    updateChecked.current = true;
    (async () => {
      try {
        const r = await rpc.checkForUpdate();
        if (r?.error) {
          console.warn("[update-check]", r.error);
          return;
        }
        if (r?.available) {
          notifs.push(
            `Update available: ${r.tag} (you have ${r.current})`,
            "info"
          );
        }
      } catch (e) {
        console.warn("[update-check]", e?.message || e);
      }
    })();
  }, [appState, notifs]);

  function toggleTheme() {
    const next = themeName === "dark" ? "paper" : "dark";
    changeTheme(next);
  }
  function changeTheme(name) {
    if (!THEMES[name]) return;
    setThemeName(name);
    localStorage.setItem("cc_theme", name);
    applyTheme(THEMES[name]);
  }
  // Restore wallpaper on mount
  useEffect(() => {
    const wp = localStorage.getItem("cc_wallpaper");
    if (wp) applyWallpaper(wp);
  }, []);

  // Splash screen
  if (showSplash) return <SplashScreen onComplete={() => setShowSplash(false)} />;

  // Disclaimer
  if (appState === "disclaimer") return (
    <ThemeCtx.Provider value={T}>
      <div style={{ background:T.bg, height:"100vh" }}>
        <Disclaimer onAccept={() => { localStorage.setItem("cc_disclaimer_accepted","1"); setAppState("onboarding"); }} T={T}/>
      </div>
    </ThemeCtx.Provider>
  );

  // Onboarding
  if (appState === "onboarding") return (
    <ThemeCtx.Provider value={T}>
      <Onboarding onComplete={() => { localStorage.setItem("cc_onboarding_done","1"); setAppState(!isWalletCreated()?"setup":"locked"); }}/>
    </ThemeCtx.Provider>
  );

  // Setup
  if (appState === "setup") return (
    <ThemeCtx.Provider value={T}><WalletSetup onComplete={() => setAppState("unlocked")}/></ThemeCtx.Provider>
  );

  // Lock
  if (appState === "locked") return (
    <ThemeCtx.Provider value={T}><Unlock onUnlock={() => setAppState("unlocked")}/></ThemeCtx.Provider>
  );

  const Page = PAGES[page] || Dashboard;

  return (
    <ThemeCtx.Provider value={T}>
      <WalletCtx.Provider value={wallet}>
        <NavCtx.Provider value={{ navigateTo }}>
        <NotifCtx.Provider value={notifs}>
          <div style={{ display:"flex", flexDirection:"column", height:"100vh", overflow:"hidden" }}>
            <TestnetBanner/>
            <div style={{ display:"flex", flex:1, overflow:"hidden", background:T.bg }}>
              <Sidebar page={page} setPage={navigateTo}
                syncInfo={wallet.syncInfo} balance={wallet.balance}
                peers={wallet.peers} seedBacked={isSeedBackedUp()}
                autoLockMinutes={Number.isFinite(autoLockMinutes) ? autoLockMinutes : 15}
                onThemeToggle={toggleTheme} isDark={themeName==="dark"} themeName={themeName} onChangeTheme={changeTheme}
                onLock={() => { lockWalletUi("Wallet locked"); }}/>
              <main style={{ flex:1, overflowY:"auto", padding:"24px 40px", background:T.bg }}>
                <div key={transitionKey} style={{
                  animation: transitioning ? "none" : "slideInRight .25s ease",
                  opacity: transitioning ? 0 : 1,
                  transition: "opacity .12s ease",
                }}>
                  <Page onThemeToggle={toggleTheme} isDark={themeName==="dark"} themeName={themeName} onChangeTheme={changeTheme}/>
                </div>
              </main>
            </div>
          </div>
          <Notifications notifs={notifs.notifs} dismiss={notifs.dismiss}/>
        </NotifCtx.Provider>
        </NavCtx.Provider>
      </WalletCtx.Provider>
    </ThemeCtx.Provider>
  );
}
