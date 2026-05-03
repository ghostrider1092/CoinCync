/**
 * Copy CoinCync node, wallet CLI, and coincync-rig (canonical retail miner)
 * from the repo workspace target/<triple>/release into
 * src-tauri/resources/binaries/ so Tauri bundles them with the desktop installer.
 *
 * Env:
 *   COINCYNC_SIDECAR_TARGET — Rust triple (e.g. x86_64-pc-windows-msvc). If unset, uses host `target/release`.
 */
const fs = require("fs");
const path = require("path");

const WALLET_DIR = path.join(__dirname, "..");
const REPO_ROOT = path.join(WALLET_DIR, "..");
const DEST = path.join(WALLET_DIR, "src-tauri", "resources", "binaries");

const triple = (process.env.COINCYNC_SIDECAR_TARGET || "").trim();
const releaseDir = triple
  ? path.join(REPO_ROOT, "target", triple, "release")
  : path.join(REPO_ROOT, "target", "release");

const names = ["coincync-node", "coincync-wallet", "coincync-rig"];

function platformExe(name) {
  return process.platform === "win32" ? `${name}.exe` : name;
}

function copyFile(src, dst) {
  fs.mkdirSync(path.dirname(dst), { recursive: true });
  fs.copyFileSync(src, dst);
  if (process.platform !== "win32") {
    try {
      const st = fs.statSync(dst);
      fs.chmodSync(dst, st.mode | 0o111);
    } catch (_) {
      /* ignore */
    }
  }
}

function main() {
  const missing = [];
  for (const base of names) {
    const fname = platformExe(base);
    const src = path.join(releaseDir, fname);
    if (!fs.existsSync(src)) {
      missing.push(src);
      continue;
    }
    const dst = path.join(DEST, fname);
    copyFile(src, dst);
    console.log(`bundled ${base} -> ${dst}`);
  }

  if (missing.length) {
    console.error(
      "\nCoinCync Wallet production build needs chain binaries in:\n  " +
        releaseDir +
        "\n\nBuild them from the repository root first, for example:\n" +
        "  cargo build --release" +
        (triple ? ` --target ${triple}` : "") +
        " --bin coincync-node --bin coincync-wallet\n" +
        "  cargo build --release" +
        (triple ? ` --target ${triple}` : "") +
        " -p coincync-rig\n"
    );
    for (const m of missing) console.error("  missing:", m);
    process.exit(1);
  }
}

main();
