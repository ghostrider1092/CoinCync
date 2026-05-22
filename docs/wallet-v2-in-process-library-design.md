<!-- markdownlint-disable MD036 MD013 -->
# Wallet v2 in-process library — design

**Status:** Design. Not yet implemented.
**Author:** 2026-05-21 wallet-wiring follow-up.
**Tracks against:** [docs/v1.0-mainnet-audit-prep.md](v1.0-mainnet-audit-prep.md) §0 (the Tauri wrapper is explicitly out of the v1.0 audit perimeter, so this refactor doesn't move the audit timeline either way) and [coincync-wallet-v2/docs/typed-errors-migration.md](../coincync-wallet-v2/docs/typed-errors-migration.md) (typed errors are a prerequisite — typed-error coverage lands incrementally before this refactor begins in earnest).

This document is a design conversation, not a release commitment. The in-process wallet refactor is **unscheduled future-work** — not slotted for v1.0 mainnet (Oct 1, 2026), the v1.0.x point-release stream (bug fixes only), or v1.1 (cyncswap-only). It's the right long-term architecture, sized for a v1.0.x or v1.1 polish window.

---

## 1. Why this exists

The v2 wallet's current architecture (inherited from v1) spawns the `coincync-wallet` CLI binary as a subprocess for every wallet operation. The Tauri command parses the CLI's stdout/stderr, string-matches errors, and updates AppState.

This works but has three structural costs documented in the [wiring conversation](../coincync-wallet-v2/docs/typed-errors-migration.md) and in [docs/v1.0-base-chain-hardening-punchlist.md](v1.0-base-chain-hardening-punchlist.md):

1. **Subprocess startup latency.** Each wallet op cold-starts the `coincync-wallet` binary. On Windows that's ~150-300 ms before the op even runs. Scanning 1000 blocks one-at-a-time = ~3-5 minutes of pure subprocess overhead before any chain work. The recent push-event wiring (`chain_state`, `wallet_state`, `mining_stats`, `tx_received`) papers over this for *display* latency but the underlying wall-clock cost is real.
2. **String-matched error handling.** Even with the typed-error layer (`WalletError`), the boundary between the Tauri command and `wallet_cli(...)` still uses substring matching to map CLI output text back to typed variants. A single change to the CLI's output format breaks the wallet silently.
3. **Password lifetime.** The session password lives in Rust memory (zeroized on drop) but is *also* passed to each subprocess via the `COINCYNC_WALLET_PASSWORD` env var. Each subprocess has its own copy in its process environment, swappable to disk, observable via `ps -e`.

The fix is to replace the subprocess pattern with direct calls into the `coincync` crate's wallet library. The Tauri process holds the unlocked `Wallet` handle for the session; every operation is a function call, no subprocess.

This is the architecture every modern wallet uses (Phantom, Rainbow, Cake, Sparrow).

---

## 2. The scope problem

`coincync-wallet-v2` is a separate Cargo workspace from the `coincync` repo. To call into `coincync::wallet` directly, it needs to depend on the wallet library.

Three options:

### Option A — Embed the full `coincync` crate as a path dep

```toml
[dependencies]
coincync = { path = "../../" }   # the main library crate
```

**Pros:** Trivial setup. All wallet functionality immediately available. No refactor in the main repo.

**Cons:** Pulls in the entire dependency tree of the `coincync` library — RandomX, RocksDB, P2P stack, consensus primitives. The Tauri binary grows from ~30 MB to ~80-120 MB. Build time goes from <30 s to several minutes. The wallet is now linked against code it never executes (mining, P2P, consensus validation). The auditor's question "what's the actual binary?" gets a worse answer.

### Option B — Extract `src/wallet/` to its own crate

```text
crates/coincync-wallet-lib/         (new)
├── Cargo.toml                       (pub deps: argon2, zeroize, ChaCha20-Poly1305, curve25519-dalek)
└── src/
    ├── lib.rs                       (re-exports wallet/, keys/, persistence/)
    ├── persistence.rs               (moved from src/wallet/persistence.rs)
    ├── scanner.rs                   (moved from src/wallet/scanner.rs)
    └── ... 14 other wallet/* files
```

The main `coincync` crate then re-exports from this crate:

```rust
// in src/wallet/mod.rs of the main coincync crate
pub use coincync_wallet_lib::*;
```

**Pros:** Cleanest architecturally. Wallet-v2 binary only links wallet code. Audit-perimeter trace is sharper. Future hardware-wallet / mobile-wallet ports inherit the same library.

**Cons:** Multi-day refactor in the main coincync repo. Touches every consensus-locked file that imports `crate::wallet::...`. Needs a lockfile re-hash (probably). Risk of breaking `cargo test --lib` in subtle ways during the move.

### Option C — Keep subprocess but optimize: long-running CLI daemon

```text
Tauri process ──spawn once──> coincync-wallet --daemon-mode
                                   ▲
                                   │
                                stdin: JSON-RPC requests
                                stdout: JSON-RPC responses
                                   │
                                   ▼
                              Wallet handle stays alive
                              across requests; no startup cost
```

**Pros:** No library extraction. No dependency-tree growth. Eliminates subprocess startup cost (the daemon stays alive for the session). Subprocess crash isolation is preserved (a wallet bug doesn't crash the Tauri UI).

**Cons:** Half-measure architecturally. Still has a subprocess boundary. Still serializes every request through JSON. Password still has to cross the boundary (on stdin? on a separate channel?). Adds a "daemon mode" to the `coincync-wallet` CLI that wasn't there before.

---

## 3. Recommended path

**Option B (extract to its own crate)**, scheduled for the v1.0.x or v1.1 polish window AFTER the v1.0 mainnet audit clears.

Reasoning:

- The architecturally-right answer is also the audit-friendliest: tighter perimeter, sharper trace, cleaner binary.
- The cost is multi-day refactor in the main repo, not novel code. Mechanical work.
- The Tauri wrapper is explicitly out of the v1.0 audit perimeter (see [docs/v1.0-mainnet-audit-prep.md](v1.0-mainnet-audit-prep.md) §0), so the refactor doesn't move the audit timeline. It runs in parallel with audit findings.
- Option C (daemon mode) is a half-measure that introduces a new IPC protocol we'd want to throw away once Option B lands. Not worth the design-and-throwaway.
- Option A (full embed) has the binary-size and build-time costs without any of the architectural benefit.

The push-event wiring shipped today (chain_state, wallet_state, mining_stats) is the foundation that makes the subprocess pattern *tolerable* in the interim. The wallet feels alive even though every op is still spawning a CLI. That gives us breathing room to extract properly rather than rush.

---

## 4. Extraction plan (Option B)

### 4.1 Repository moves

```text
src/wallet/                           ──► crates/coincync-wallet-lib/src/
├── balance.rs                        (move)
├── background_sync.rs                (move)
├── churn.rs                          (move)
├── history.rs                        (move)
├── key_epoch.rs                      (move)
├── keys.rs                           (move)
├── lightsync.rs                      (move)
├── mnemonic.rs                       (move)
├── multisig.rs                       (move; FROST-coord touch — see §4.3)
├── persistence.rs                    (move; v4-format work depends on this)
├── scanner.rs                        (move)
├── send.rs                           (move)
├── subaddress.rs                     (move)
├── tx_decode.rs                      (move)
├── wallet.rs                         (move; the top-level Wallet handle)
└── wallet_keys.rs                    (move)
```

### 4.2 Dependency tree

`crates/coincync-wallet-lib/Cargo.toml` (new):

```toml
[package]
name = "coincync-wallet-lib"
version = "0.1.0"
edition = "2021"

[dependencies]
# Crypto (already in main coincync Cargo.toml)
argon2          = { workspace = true }
chacha20poly1305 = { workspace = true }
curve25519-dalek = { workspace = true }
blake3          = { workspace = true }
ed25519-dalek   = { workspace = true }
zeroize         = { workspace = true }
subtle          = { workspace = true }

# Serialization
borsh           = { workspace = true }
serde           = { workspace = true }

# Primitives (will need to be themselves extracted or pulled from main)
coincync-primitives = { path = "../coincync-primitives" }   # if also extracted
# OR
# (re-export Hash / Amount / KeyImage from a thin shared crate)

# Utils
bip39           = { workspace = true }
hex             = { workspace = true }
rand            = { workspace = true }
parking_lot     = { workspace = true }
tracing         = { workspace = true }
```

The primitives dependency is the trickiest part. `src/wallet/` uses `crate::primitives::{Hash, Amount, KeyImage, ...}` extensively. Three sub-options:

- **B.1**: Also extract `crates/coincync-primitives/` first. Cleanest, more work.
- **B.2**: Wallet-lib defines its own minimal `Hash`/`Amount`/`KeyImage` newtypes and converts at the boundary. Doable but adds friction.
- **B.3**: Wallet-lib re-exports primitives from the main `coincync` crate, which it path-deps. Coupling stays but it's a known coupling.

Recommend **B.1** — bite the primitives extraction at the same time. Both are mechanical moves.

### 4.3 FROST coord integration

`src/wallet/multisig.rs` integrates with `crates/coincync-frost-coordinator/`. The FROST coord crate is a workspace member already, so this becomes a simple dependency declaration in the new `coincync-wallet-lib/Cargo.toml`. No additional move needed.

### 4.4 Public API surface

What `coincync-wallet-lib` exposes:

```rust
// crates/coincync-wallet-lib/src/lib.rs

pub use wallet::Wallet;                   // top-level handle
pub use persistence::{create_wallet, load_wallet, save_wallet};
pub use scanner::Scanner;
pub use send::SendParams;
pub use balance::Balance;
pub use history::TransactionHistory;
pub use mnemonic::WalletMnemonic;
pub use key_epoch::{KeyEpoch, ScopedViewKey};
pub use multisig::{FrostSession, /* etc. */};
pub use background_sync::BackgroundSyncManager;

// Errors
pub use error::{WalletError, Result};
```

The `WalletError` defined here REPLACES the wallet-v2-local `WalletError` enum currently in `coincync-wallet-v2/src-tauri/src/main.rs`. The wallet-v2 binary re-exports it for use in Tauri command signatures.

### 4.5 Tauri command refactor

Each command goes from "spawn CLI + parse output" to "call library function":

```rust
// BEFORE (wallet-v2's main.rs)
fn unlock_wallet(password: String, ...) -> Result<bool, WalletError> {
    let bin = state.lock()?.wallet_bin.clone();
    let path = wallet_dir().join("default.wallet");
    if let Err(err) = wallet_cli(&bin, &["--wallet", &p, "open"], &password) {
        return Err(WalletError::from_cli_error(err));
    }
    // ... update state, emit event
}

// AFTER
fn unlock_wallet(password: String, ...) -> Result<bool, WalletError> {
    let path = wallet_dir().join("default.wallet");
    let wallet = coincync_wallet_lib::load_wallet(&path, &password)?;
    {
        let mut s = state.lock()?;
        s.wallet = Some(wallet);                  // wallet handle lives in AppState
        s.unlocked = true;
        emit_wallet_state(&app, &s);
    }
    Ok(true)
}
```

The session password no longer crosses a subprocess boundary — `load_wallet` derives the key, decrypts, returns the unlocked `Wallet`, and the password can be zeroized immediately.

### 4.6 AppState changes

```rust
struct AppState {
    // BEFORE
    wallet_bin: String,                      // path to CLI binary
    wallet_path: PathBuf,
    password: Option<String>,                // session password
    balance_total: u64,
    balance_unlocked: u64,
    utxo_count: usize,
    scanned_height: u64,
    transactions: Vec<TxRecord>,
    unlocked: bool,
    // ...

    // AFTER
    wallet: Option<coincync_wallet_lib::Wallet>,  // the unlocked wallet handle
    // (the cached balance/utxo/scan fields all move into the Wallet
    //  struct itself; AppState just holds the handle and queries when needed)
    // ...
}
```

The cached state fields (`balance_total`, `balance_unlocked`, etc.) move INTO the `Wallet` struct. The Tauri commands read from `wallet.balance()`, `wallet.utxo_count()`, `wallet.scanned_height()` instead of from AppState. AppState shrinks substantially.

### 4.7 What stays the same

- The Tauri command names and JS-side `invoke()` signatures. JS code is unchanged.
- The push-event channels (`chain_state`, `wallet_state`, `mining_stats`, `tx_received`). They emit from the new in-process path the same way they emitted from the subprocess path.
- The typed-error enum naming. `WalletError::AuthInvalidPassword` keeps its name; only its origin changes (now thrown by the library, not mapped from CLI output).
- The audit perimeter for the wallet library (`src/wallet/` → `crates/coincync-wallet-lib/src/`). Same code, moved file path, same audit-firm review scope.

---

## 5. Migration path

This is bigger than the wallet-file v4 migration. Phased:

**Phase 1 (prep, ~1-2 days):**

- Extract `src/wallet/` to `crates/coincync-wallet-lib/`
- Extract `src/primitives/` to `crates/coincync-primitives/` (if going with B.1)
- Main `coincync` crate re-exports from these so existing call sites compile unchanged
- All 585 lib tests still pass
- `critical_files.lock` re-hashed (the move probably affects validation.rs imports)

**Phase 2 (wire-up, ~2-3 days):**

- Add `coincync-wallet-lib = { path = "../../crates/coincync-wallet-lib" }` to wallet-v2's Cargo.toml
- Add `wallet: Option<Wallet>` to AppState
- Refactor `unlock_wallet`, `lock_wallet`, `create_wallet`, `restore_wallet` to use the library
- Both subprocess AND in-process paths coexist behind a feature flag during transition
- Verify push events still fire correctly
- Audit-firm-style test: tamper with a wallet file, confirm the in-process path rejects it the same way the subprocess path did

**Phase 3 (cutover, ~1 day):**

- Refactor remaining 29 commands to use the library
- Remove the `wallet_cli` subprocess function
- Remove the `wallet_bin` field from AppState
- Tauri binary no longer needs `coincync-wallet` as a sidecar resource
- `tauri.conf.json` `resources/binaries/` shrinks

**Phase 4 (polish, ~half day):**

- Remove the legacy string-fallback branch in JS `formatWalletError`
- Remove `WalletError::from_cli_error` substring-matching (no more CLI errors to map)
- Tighten documentation and changelog

**Total estimate:** 4-7 focused days. Not a session; a small project.

---

## 6. Risks

- **Library extraction touches consensus-adjacent code.** Moving `src/wallet/` files changes their imports, which means changes to other files in the audit perimeter that import them. Lockfile re-hash unavoidable.
- **Behavior changes silently.** Some subprocess invocations have legacy quirks (string parsing tolerates whitespace variants, error messages match by substring). The in-process path won't replicate those quirks unless tested for. Need a parity test suite.
- **AppState refactor is invasive.** The cached `balance_total`/`utxo_count`/etc. fields are referenced in many places. Moving them into `Wallet` is a wide-touch change.
- **Tauri binary still ships `coincync-node`, `coincync-rig`, `cyncswap` as sidecar resources.** Only `coincync-wallet` goes away. Operators who used the wallet's bundled binaries directly are unaffected.

---

## 7. Open questions deferred to implementation time

1. **Primitives extraction vs. inline copy** (option B.1 vs B.2). Recommend B.1 for cleanliness but B.2 is faster.
2. **`Wallet` handle lifetime** — is it `Option<Wallet>` inside `Mutex<AppState>`, or is it its own `Arc<RwLock<Wallet>>` outside AppState? The latter allows concurrent reads (`get_balance` doesn't block `scan_wallet`).
3. **Background-sync ownership** — `BackgroundSyncManager` is currently a wallet-library type that the wallet-v2 binary doesn't yet use. In the in-process world, the Tauri side spawns the sync manager. Where does it live in AppState?
4. **What happens to the `coincync-wallet` CLI** — is it still shipped as a standalone tool for power users, or does it become an "internal-only" binary? Recommend: keep shipping it (operators may want CLI access for scripting), but the wallet GUI no longer depends on it.

---

## 8. Out of scope

- **In-process mining.** `coincync-rig` stays as a subprocess. Its metrics are already scraped via the /metrics endpoint wiring (see [src-tauri/src/main.rs](../coincync-wallet-v2/src-tauri/src/main.rs) `fetch_rig_metrics`). Mining is a long-running, isolated workload; embedding it doesn't have the same audit/posture benefit as embedding the wallet does.
- **In-process node.** `coincync-node` stays as a subprocess. The wallet talks to it over JSON-RPC. Embedding the full node would defeat the "thin wallet" architecture.
- **In-process atomic swap (cyncswap).** v1.1 work; tracked separately. The cyncswap audit doesn't touch this refactor.

---

## 9. Decision log

- **2026-05-21** — Design doc opened. Push-event wiring (chain_state / wallet_state / mining_stats / tx_received) shipped today, which is the foundation that makes the subprocess pattern tolerable in the interim. Typed-error coverage for auth + scan + send + mining commands also shipped. The in-process refactor is now genuinely "next step" but not slotted for v1.0; queued for the v1.0.x or v1.1 polish window. Recommend Option B (extract wallet to its own crate) over A (full embed) or C (daemon mode).

---

*This is a design document, not an implementation commitment. The source-of-truth for wallet architecture remains the code in `coincync-wallet-v2/` and `src/wallet/` until this refactor is implemented and merged. Discrepancies between this document and the code should be resolved in favor of the code; discrepancies between this document and the intent above should be resolved by updating either, with a note in §9.*
