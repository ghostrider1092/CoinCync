# CoinCync Debugger — VS Code extension

VS Code glue for the `coincync-dbg` DAP adapter. The debugger logic lives in the
Rust binary (`crates/coincync-dbg`); this extension only registers the
`coincync-dbg` debug type and tells VS Code how to launch the adapter.

## Install (development)

1. Build the adapter from the repo root:
   ```bash
   cargo build -p coincync-dbg --release
   ```
2. Install this extension's dependency-free package into VS Code:
   - Copy this folder into `~/.vscode/extensions/coincync-dbg-0.1.0/`, **or**
   - Open this folder in VS Code and press **F5** (Extension Development Host),
     **or**
   - Package it with [`vsce`](https://github.com/microsoft/vscode-vsce):
     `npx @vscode/vsce package` → install the generated `.vsix` via the
     Extensions view → "Install from VSIX…".
3. The extension auto-detects the adapter at `target/release/coincync-dbg` (then
   `target/debug/`), else PATH. Override with the setting
   `coincync-dbg.adapterPath` if yours is elsewhere.

## Use

1. **Run and Debug** (Ctrl+Shift+D) → **"CoinCync: difficulty replay (floor
   breakpoint)"** → **F5**.
2. The adapter replays difficulty retargeting and **pauses when difficulty hits
   the floor**. The **Variables** pane shows the decoded block state
   (`height`, `gap_secs`, `target`, `difficulty`, `at_floor`); the **Debug
   Console** prints the collapse line.
3. Step with **F10/F11**; **Continue (F5)** runs to the next floor hit.
4. Set a line breakpoint in the generated `*.ccscenario` source to pause at a
   specific block instead.

### launch.json

```jsonc
{
  "type": "coincync-dbg",
  "request": "launch",
  "name": "CoinCync: difficulty replay",
  // Optional: pause when difficulty <= MIN_DIFFICULTY * floorMultiple.
  "floorMultiple": 2
}
```

## Other IDEs

The adapter is a standard DAP server over stdio, so it works unchanged
elsewhere — e.g. Neovim with `nvim-dap`:

```lua
local dap = require("dap")
dap.adapters["coincync-dbg"] = {
  type = "executable",
  command = "coincync-dbg", -- or an absolute path to the built binary
}
dap.configurations.rust = {
  { type = "coincync-dbg", request = "launch", name = "Difficulty replay" },
}
```
