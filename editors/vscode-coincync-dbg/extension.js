// Minimal VS Code glue for the CoinCync DAP adapter.
//
// All the debugger logic lives in the Rust `coincync-dbg` binary; this file
// only tells VS Code how to launch it. The same adapter works unchanged in any
// DAP-capable IDE (Neovim/nvim-dap, JetBrains, Emacs/dap-mode) — those just need
// their own one-time "run this executable as a DAP server" registration.

const vscode = require("vscode");
const path = require("path");
const fs = require("fs");

/** Locate the built adapter binary under the workspace target dir, else PATH. */
function findAdapter(folder) {
  const names = process.platform === "win32" ? ["coincync-dbg.exe"] : ["coincync-dbg"];
  const dirs = ["target/release", "target/debug"];
  if (folder) {
    for (const d of dirs) {
      for (const n of names) {
        const p = path.join(folder.uri.fsPath, d, n);
        if (fs.existsSync(p)) return p;
      }
    }
  }
  return "coincync-dbg"; // rely on PATH
}

function activate(context) {
  const factory = {
    createDebugAdapterDescriptor(session) {
      const cfg = vscode.workspace.getConfiguration("coincync-dbg");
      const explicit = cfg.get("adapterPath");
      const adapter =
        explicit && explicit.length > 0 ? explicit : findAdapter(session.workspaceFolder);
      // The adapter speaks DAP over stdio.
      return new vscode.DebugAdapterExecutable(adapter, []);
    },
  };

  context.subscriptions.push(
    vscode.debug.registerDebugAdapterDescriptorFactory("coincync-dbg", factory)
  );

  // Provide a default launch config if the user has none.
  const provider = {
    resolveDebugConfiguration(_folder, config) {
      if (!config.type) {
        config.type = "coincync-dbg";
        config.request = "launch";
        config.name = "CoinCync: difficulty replay (floor breakpoint)";
      }
      return config;
    },
  };
  context.subscriptions.push(
    vscode.debug.registerDebugConfigurationProvider("coincync-dbg", provider)
  );
}

function deactivate() {}

module.exports = { activate, deactivate };
