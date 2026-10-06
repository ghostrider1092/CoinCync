//! CoinCync Debug Adapter Protocol (DAP) server — vertical slice.
//!
//! A universal, IDE-agnostic debugger for CoinCync built on DAP: one Rust
//! adapter speaks the protocol every modern IDE already knows, so VS Code,
//! Neovim and JetBrains all get a native debugging UI with no per-editor
//! plugin. This first slice debugs ONE real consensus behaviour — difficulty
//! retargeting — with a semantic breakpoint ("difficulty reaches the floor",
//! the #191 collapse) that has no analogue in a generic line debugger.
//!
//! Layers:
//! - [`engine`]   — the debuggee: deterministic replay over the REAL
//!                  `calculate_difficulty`, stepping block-by-block.
//! - [`protocol`] — DAP Content-Length framing over any reader/writer.
//! - [`session`]  — the DAP state machine mapping requests to engine steps.
//!
//! The binary (`src/main.rs`) wires `session` to stdin/stdout; a VS Code
//! extension under `editors/vscode-coincync-dbg/` registers the `coincync-dbg`
//! debug type so the IDE launches this adapter.

pub mod engine;
pub mod protocol;
pub mod session;
