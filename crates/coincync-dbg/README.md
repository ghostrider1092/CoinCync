# coincync-dbg — a DAP debugger for CoinCync consensus

A universal, IDE-agnostic debugger for CoinCync, built on the **Debug Adapter
Protocol (DAP)**. One Rust adapter speaks the protocol every modern IDE already
knows, so VS Code, Neovim (nvim-dap), JetBrains and Emacs (dap-mode) all get a
native debugging UI — breakpoints, stepping, call stack, variables — with no
per-editor plugin to write.

This is the **vertical slice**: it debugs one real consensus behaviour end to
end, to de-risk the architecture against actual chain state rather than a
generic vision.

## What it does today

Replays CoinCync **difficulty retargeting** through the *real*
`coincync::consensus::difficulty::calculate_difficulty`, one block at a time,
and exposes a **semantic breakpoint** a normal line debugger can't:

> **difficulty-floor** — pause the moment ASERT drives difficulty to
> `MIN_DIFFICULTY`. That's the exact symptom of issue **#191** (difficulty
> collapse after an idle/slow gap). Stepping the replay makes the collapse
> observable block-by-block, and the Variables pane decodes the true state:
> `height`, `gap_secs`, `target` (hex), `difficulty`, `at_floor`.

Stepping a *block* is the domain analogue of stepping a *source line*; a
cryptographic/consensus invariant is the domain analogue of an *exception
breakpoint*.

Supported DAP requests: `initialize`, `launch`, `setBreakpoints` (line
breakpoints on the scenario source), `setExceptionBreakpoints`
(`difficulty-floor`), `configurationDone`, `threads`, `stackTrace`, `scopes`,
`variables`, `continue`, `next`/`stepIn`/`stepOut`, `disconnect`/`terminate`.

## Architecture

| Layer | File | Role |
|-------|------|------|
| Engine (debuggee) | `src/engine.rs` | Deterministic replay over the real `calculate_difficulty`; decodes per-block state; evaluates the floor condition. |
| Protocol | `src/protocol.rs` | DAP `Content-Length` framing over any `BufRead`/`Write`. |
| Session | `src/session.rs` | DAP state machine: maps requests to engine steps and emits `stopped`/`terminated`/`output` events. |
| Binary | `src/main.rs` | Wires the session to stdin/stdout (how an IDE launches a DAP adapter). |
| IDE glue | `../../editors/vscode-coincync-dbg/` | ~40 lines registering the `coincync-dbg` debug type in VS Code. |

Everything in the engine is **pure and deterministic**, which is the
precondition for the planned next increments.

## Why CoinCync can go further than a generic crypto debugger

The correctness-program enablers already in the tree make the hard parts
feasible:

- **Deterministic replay** (E1 clock seam, E3 seeded RNG, E2 transport seam, F2
  DST switchboard) → `stepBack` / `reverseContinue` (time-travel) are a matter
  of re-running to position *N*, not a new infrastructure.
- **Coded invariants `CYNC-*` (F3) + flight recorder (F5)** are already a stream
  of semantic events → each becomes a breakpoint condition (missing ring member
  #219, balance-proof failure SHLD-001, reorg depth, …).

## Roadmap

1. ✅ Difficulty replay + `difficulty-floor` breakpoint + line breakpoints.
2. More semantic breakpoints wired from the invariant / flight-recorder hooks.
3. `stepBack` / `reverseContinue` via replay-to-N.
4. Richer debuggees: block validation, CLSAG ring + decoy inspection, mempool,
   reorg. (ZK/Spark once that engine is wired in; **no FHE/TEE** — CoinCync has
   neither.)

## Build & try

```bash
# Build the adapter (uses the pinned 1.88 toolchain + testnet feature).
cargo build -p coincync-dbg --release

# Run the full test suite for the adapter (protocol + engine).
cargo test -p coincync-dbg
```

To use it in VS Code, see `editors/vscode-coincync-dbg/README.md`. The adapter
speaks DAP over stdio, so any DAP client can drive it.
