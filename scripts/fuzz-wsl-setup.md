<!-- markdownlint-disable-file MD041 MD013 -->

# Fuzz on WSL — one-time bootstrap

cargo-fuzz on Windows can't link the ASAN runtime (it's not in MSVC).
Linux ships ASAN out of the box. This is the 3-step path from a blank
Windows machine to a running fuzz.

## Step 1 — install WSL Ubuntu (PowerShell, admin)

```powershell
# Run as Administrator. Reboot if prompted; this is one-time.
wsl --install -d Ubuntu

# After reboot, Ubuntu launches automatically and asks you to set a
# username + password. Pick anything; you'll use them for sudo.
```

If you already have WSL Ubuntu, skip this step.

## Step 2 — get the coincync source into WSL

**Important: clone into the WSL filesystem (`~/coincync`), not `/mnt/c/`.**
`/mnt/c/` is the Windows-to-WSL bridge and is ~10× slower for any I/O-heavy
operation, which a `cargo build` very much is.

From inside WSL:

```bash
# Option A — fresh clone from origin (preferred if your fleet pulls
# from the same remote)
git clone https://github.com/<you>/coincync.git ~/coincync

# Option B — rsync from your Windows-side checkout (preserves local
# changes that aren't pushed). Tedious but works.
rsync -av --exclude target --exclude '.git/objects/pack' \
      '/mnt/c/dev/coincync/' \
      ~/coincync/
```

## Step 3 — run the setup script

```bash
cd ~/coincync
bash scripts/fuzz-wsl-setup.sh
```

The script installs apt prereqs, rustup + nightly + `cargo-fuzz`, and
compiles `fuzz_p2p_message` to verify the toolchain works. First cold
compile takes 5–15 minutes; subsequent fuzz runs launch in seconds.

## Step 4 — run a fuzz target

```bash
cd ~/coincync

# 60-second smoke (proves the harness runs)
cargo +nightly fuzz run fuzz_p2p_message -- -max_total_time=60

# 1-hour overnight pass (real bugs start to surface here)
cargo +nightly fuzz run fuzz_p2p_message -- -max_total_time=3600
```

Five targets are registered:

```text
fuzz_p2p_message    network-reachable P2P message parsing
fuzz_block          block validation
fuzz_transaction    transaction validation
fuzz_clsag          CLSAG ring signature parsing
fuzz_stealth        stealth address derivation
```

Auditor-grade runs go 24+ hours per target. Run them one at a time so
each gets the full CPU; rotate nightly.

## Step 5 — handle crashes

Crashes land at `fuzz/artifacts/<target>/crash-*`. For each:

```bash
# Minimize the input to the smallest reproducer
cargo +nightly fuzz tmin fuzz_p2p_message fuzz/artifacts/fuzz_p2p_message/crash-<hash>

# Print the failing input as hex for inclusion in a regression test
xxd fuzz/artifacts/fuzz_p2p_message/minimized-from-<hash>
```

Then promote to a permanent regression test:

1. Add an entry to [`audit-suite/regression-corpus/cves.json`](../audit-suite/regression-corpus/cves.json)
   with the minimized bytes as the `fixture` field.
2. Add a Rust unit test in the affected crate that re-feeds the bytes
   and asserts safe rejection.
3. Move the crash file from `fuzz/artifacts/<target>/` into the seed
   corpus at `audit-suite/corpus/<target>/` so the fuzzer keeps it as
   a permanent input (catches re-introduction).

## Optional — run on a Vultr fleet box instead of local WSL

If you'd rather burn cycles on a Vultr box (more CPU, can run overnight
without touching your dev laptop), the same `fuzz-wsl-setup.sh` works
on any of the fleet IPs:

```powershell
# From Windows PowerShell, push source via rsync + run remotely
$IP = "207.148.6.50"  # explorer is least latency-sensitive
ssh -i ~/.ssh/coincync_fleet root@$IP "mkdir -p /tmp/coincync-fuzz"
scp -i ~/.ssh/coincync_fleet -r . root@${IP}:/tmp/coincync-fuzz/
ssh -i ~/.ssh/coincync_fleet root@$IP "
  cd /tmp/coincync-fuzz &&
  bash scripts/fuzz-wsl-setup.sh &&
  nohup cargo +nightly fuzz run fuzz_p2p_message -- -max_total_time=3600 \
        > /tmp/fuzz-p2p.log 2>&1 &
"
```

**Caveat (per project memory):** the Vultr fleet boxes are running the
public testnet soak. cargo-fuzz will burn CPU + memory and may
destabilize the soak. Prefer your local WSL unless you really want a
spare box dedicated to fuzz. If you go fleet route, pick `explorer`
(207.148.6.50) — least consensus-critical role.
