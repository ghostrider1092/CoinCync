# `regtest-fast` — instant-mining dev mode (#3)

**Status: APPLIED + live-verified (2026-08-22).** Off by default; the
feature-off (production) build is byte-for-byte behavior-identical and passes
the critical-file integrity lock. Two hash-locked files changed
(`difficulty.rs`, `validation.rs`) and the lock was regenerated
(`update-critical-hashes`); only those two lines changed in `critical_files.lock`.

## Why

A fresh regtest chain on the real 120s-target ASERT spikes difficulty from the
fast early blocks (observed live up to 720k) and then crawls, so a full
receive→send→spend E2E took hours. This mode pins regtest difficulty to a fixed
low value so blocks mine quickly and difficulty never oscillates — turning the
whole E2E into a minutes-long, CI-able check.

## Design (minimal + safe)

A cargo feature `regtest-fast`, **off by default**, gates two `#[cfg]` blocks:

1. **`src/consensus/difficulty.rs` — `calculate_difficulty`:** early-returns a
   **fixed** target `Hash::from_difficulty(1024)`. Both the miner and the
   validator call this one function, so they stay consistent automatically.
   *(Not `max_target()`/difficulty-1: that lets every hash win, so the miner
   floods block commits in a tight loop and starves the chain write-lock,
   making RPC unresponsive. A fixed 1024 gives fast-but-controlled mining,
   ~1 block/s in the live test.)*
2. **`src/consensus/validation.rs` — `validate_difficulty_target`:** early-return
   bypassing the target-sanity checks (max-target floor, non-zero, and the
   inter-block ±32× adjustment-ratio clamp). The first pinned block is a large,
   intentional drop from the genesis difficulty, which the clamp would otherwise
   reject.

Both blocks are behind `#[cfg(feature = "regtest-fast")]` with a scoped
`#[cfg_attr(feature = "regtest-fast", allow(unreachable_code, unused_variables))]`
so the dev build is warning-clean. Production builds compile neither block.

**NEVER build mainnet or public testnet with this feature.**

## Build + use

```powershell
# testnet feature = coinbase maturity 10 (vs 100); regtest-fast = fixed difficulty
cargo build --release --features "testnet regtest-fast" --bin coincync-node --bin coincync-wallet
coincync-node --network regtest --data-dir <dir> --no-peers --mine <ADDRESS>
```

A fresh regtest node then mines to a spendable height in ~a minute.

## Live verification (2026-08-22)

Full loop completed on a real regtest-fast node, all real crypto:
- Difficulty pinned at **1024**, ~1 block/s, RPC responsive.
- Wallet receive (scan) → real privacy **send** (mined).
- **Subaddress** create → **receive** (verified via `wallet utxos`: a 5-CYNC
  output tagged `subaddress 0/1`) → **spend**: a follow-up send consumed it, and
  `wallet utxos --include-spent` shows that exact output flip to `spent: yes`
  after the spend mined. That is the decisive live proof that a subaddress
  offset-derived key produces a valid, block-accepted spend.

## If you ever need to re-lock

Because `difficulty.rs` / `validation.rs` are integrity-locked, any further edit
requires (in an elevated shell if your environment needs it):

```powershell
$env:COINCYNC_REGEN_LOCK = "1"
cargo run --locked --bin update-critical-hashes
```

Review the `critical_files.lock` diff (only the intended files should change).
