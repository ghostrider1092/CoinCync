# CIP — Activating the shielded (Spark) pool on testnet

**Status:** planned rollout, not yet executed. **Decision owner:** project lead
(informed call, 2026-10-19). **Scope:** testnet only. **Mainnet is untouched and
stays audit-gated.**

## Why

The external audit takes months; users on the public testnet want to exercise
shielded now, and testnet exists precisely to run pre-audit code under realistic
multi-node conditions and surface bugs that isolated soaks and the beta net
cannot. Live testnet metrics also make the eventual audit cheaper (bugs found and
fixed before it starts). Testnet coins have no value, so the fund-safety risk the
audit gates does not apply there.

**What this does NOT change:** mainnet `SHIELDED_TX_ACTIVATION_HEIGHT` stays
`u64::MAX`. Real value remains gated behind the external audit. This rollout is a
testnet-only activation for data and dogfooding.

## The one real risk: forking the live testnet fleet

Shielded block/tx verification is compiled only under
`sketch-gk-proof + libspark-ffi`. A node built **without** those features cannot
validate a shielded block — it will reject it. The live testnet fleet (seed
`2.29.34.197`) currently runs plain `--features testnet` binaries with no
libspark. So the instant shielded activates, every non-libspark node forks off.

Therefore activation is a **coordinated hard fork**, not a flag flip. The
standard testnet build must change:

```
  OLD:  --features testnet
  NEW:  --features "testnet sketch-gk-proof libspark-ffi"
```

Every testnet node — fleet and community — must run the new build before the
activation height, and every node now carries an **OpenSSL dependency** (see the
build recipe below).

## Prerequisite — DONE (2026-10-19)

`libspark-ffi` now builds and runs correctly on **Linux**, which it previously
could not (it was MSVC-only). This unblocks the Linux fleet. Verified this
session on WSL (Ubuntu, clang-18, rustc 1.88.0):

- `spark-connector --features libspark-ffi` compiles on Linux.
- Connector gated crypto suite: **23 passed / 0 failed** (self-test, build→verify
  loop, transfer+recovery, mint value authentication, spend-tag extraction,
  solvency) — the 64-bit-limb path is correct.
- Full `coincync-node --features "testnet sketch-gk-proof libspark-ffi"` builds to
  a Linux x86-64 ELF.

Fixes that made it portable (all in our shim/build layer; **no Firo crypto
modified** — see `cip-shielded-libspark-portability.md`): `build.rs` target-gates
the secp256k1 limb backend (MSVC `10x26`/`8x32`; Linux `5x52`/`4x64` +
`HAVE___INT128`), the glibc endian defines, the Windows-only platform defines and
link libs (`libcrypto`→`crypto`); `shim.cpp` uses a portable `CDataStream::write`
append.

### Linux node build recipe (for operators)

```bash
sudo apt-get install -y libssl-dev clang   # OpenSSL dev + clang
export SPARK_OPENSSL_DIR=/usr
export LIBCLANG_PATH=/usr/lib/llvm-18/lib
cargo build --release --locked --bin coincync-node \
  --features "testnet sketch-gk-proof libspark-ffi"
```

(Windows/MSVC operators keep the existing vcpkg `x64-windows-static-md` OpenSSL
prefix as `SPARK_OPENSSL_DIR`.)

## Rollout sequence

1. **Confirm both platforms build the shielded testnet node** — Linux (done) and
   MSVC (the full gated lib suite must stay `0 failed`; the portability edits are
   byte-identical on MSVC).
2. **Publish libspark-capable testnet binaries** (Linux + Windows) and update the
   node/runbook docs so the standard testnet build is the shielded one.
3. **Upgrade the fleet** at `2.29.34.197` and announce to community node
   operators, with the OpenSSL dependency called out.
4. **Set a future activation height.** Edit `SHIELDED_TX_ACTIVATION_HEIGHT` (or
   the testnet arm of `shielded_activation_height`) in `constants.rs` off
   `u64::MAX` to a height comfortably beyond the slowest expected upgrade window.
   `constants.rs` is **hash-locked** → regenerate `critical_files.lock`
   (`COINCYNC_REGEN_LOCK=1`), run the full gated suite, commit.
5. **Let the network cross the height together.** Before it, shielded txs are
   rejected (as today); at/after it, upgraded nodes accept them in lock-step.
   Un-upgraded nodes fork off — expected and announced.
6. **Mainnet arm stays `u64::MAX`.** Verify the change touches only the testnet
   arm.

## Safety / rollback

- The activation height is in the **future** until it is reached. If a blocking
  bug surfaces during the upgrade window, push the height further out (another
  coordinated release) before it passes — cheap.
- Once the height passes it is consensus history on testnet; "rolling back" then
  means a testnet reset, not a quiet revert. So the pre-height soak + metrics
  window matters.
- Shielded has a 24h soak at the ratified N=512 (0 anomalies), extensive live
  beta E2E, and the 7 live-caught bug-classes already fixed. Testnet activation
  widens that to real multi-node conditions — the point of the exercise.

## Open questions for the decision owner

- **Activation height** and the upgrade-window length.
- **Beta net** disposition: keep it as the bleeding-edge net, or fold its role
  into testnet once shielded is live there.
- Whether to **strip** the release Linux node (the dev build is ~496 MB
  unstripped; `--release` + strip for distribution).
