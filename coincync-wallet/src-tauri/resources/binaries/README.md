# Bundled chain binaries

Production installers include **coincync-node**, **coincync-wallet**, and **coincync-tui-miner** copied here by `npm run bundle:sidecars` (runs automatically before `tauri build`).

From the repository root, build them once:

```bash
cargo build --release --features "randomx testnet" --bin coincync-node --bin coincync-wallet --bin coincync-tui-miner
```

For a cross-target CI build, set `COINCYNC_SIDECAR_TARGET` to the same Rust triple as `cargo build --target …`.
