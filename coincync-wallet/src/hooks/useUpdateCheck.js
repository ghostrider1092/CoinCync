import { useEffect, useState } from "react";

const DEFAULT_MANIFEST_URL =
  import.meta.env.VITE_UPDATE_MANIFEST_URL ||
  "https://releases.coincync.network/wallet/latest.json";

const DISMISS_KEY = "cc_update_dismissed_version";
const CHECK_DELAY_MS = 5000;
const CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000;

function parseSemver(v) {
  const m = String(v || "").match(/^(\d+)\.(\d+)\.(\d+)/);
  return m ? [+m[1], +m[2], +m[3]] : null;
}

function isNewer(latest, current) {
  const a = parseSemver(latest);
  const b = parseSemver(current);
  if (!a || !b) return false;
  for (let i = 0; i < 3; i++) {
    if (a[i] > b[i]) return true;
    if (a[i] < b[i]) return false;
  }
  return false;
}

export function useUpdateCheck() {
  const [state, setState] = useState({
    available: false,
    latestVersion: null,
    releaseDate: null,
    releaseNotesUrl: null,
    downloadUrl: null,
    notes: null,
    releases: [],
  });

  useEffect(() => {
    const current = typeof __APP_VERSION__ !== "undefined" ? __APP_VERSION__ : "0.0.0";

    async function check() {
      try {
        const res = await fetch(DEFAULT_MANIFEST_URL, { cache: "no-store" });
        if (!res.ok) return;
        const m = await res.json();
        const latest = m.version;
        if (!isNewer(latest, current)) return;
        if (localStorage.getItem(DISMISS_KEY) === latest) return;

        const platformKey =
          navigator.platform && navigator.platform.toLowerCase().includes("win")
            ? "windows-x86_64"
            : navigator.platform && navigator.platform.toLowerCase().includes("mac")
            ? "darwin-x86_64"
            : "linux-x86_64";
        const downloadUrl =
          (m.platforms && m.platforms[platformKey]) || m.download_url || null;

        setState({
          available: true,
          latestVersion: latest,
          releaseDate: m.release_date || null,
          releaseNotesUrl: m.release_notes_url || null,
          downloadUrl,
          notes: m.notes || null,
          releases: Array.isArray(m.releases) ? m.releases : [],
        });
      } catch {
        // network failure / DNS — silently no-op; banner just doesn't appear
      }
    }

    const t = setTimeout(check, CHECK_DELAY_MS);
    const i = setInterval(check, CHECK_INTERVAL_MS);
    return () => {
      clearTimeout(t);
      clearInterval(i);
    };
  }, []);

  function dismiss() {
    if (state.latestVersion) {
      localStorage.setItem(DISMISS_KEY, state.latestVersion);
    }
    setState((s) => ({ ...s, available: false }));
  }

  return { ...state, dismiss };
}
