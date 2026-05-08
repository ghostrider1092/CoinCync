# Continuous fuzzing — runbook

**What:** keep the existing 5 cargo-fuzz targets running 24/7
on a dedicated machine. Crashes file an alert to Discord and
land artifacts on disk for triage.

**Why:** ad-hoc fuzz runs find easy bugs once. Continuous
fuzzing finds the bugs that take billions of iterations or
months of corpus growth. Heartbleed, CVE-2024-0193, and most
high-impact memory-corruption bugs in production code were
found by continuous fuzzers long after manual runs declared
the code "fine."

**Two paths.** Self-hosted (works today) and OSS-Fuzz (free
Google service, requires public repo). Start self-hosted, add
OSS-Fuzz post-launch when the public repo on
git.coincync.network is live.

---

## Path A — self-hosted (today)

### Where to run it

You don't want fuzzing on the api box (competes with the
rig + node + faucet for CPU). The `seedN` boxes have
lighter workloads and spare cycles. Pick one:

- **seed3 (Tokyo)** — closest to operator if Japan-based
- **seed1 (NJ)** — most spare CPU per the soak summary
- A separate dedicated VPS — best isolation, ~$5/mo at
  Hetzner / Vultr for a 4GB / 2vCPU box

Recommendation: dedicated VPS. ~$60/year is cheap insurance
against missing a critical bug.

### Setup steps (~30 min one-time)

1. **Install dependencies** on the target box:

   ```bash
   apt-get update
   apt-get install -y curl build-essential pkg-config libssl-dev cmake clang lld
   curl https://sh.rustup.rs -sSf | sh -s -- -y
   source $HOME/.cargo/env
   cargo install cargo-fuzz
   ```

2. **Mirror the source tree** to the box. Two options:

   - **Read-only git pull from a mirror** (if the repo is
     hosted somewhere accessible — Forgejo at
     `git.coincync.network` once that's up):
     ```bash
     mkdir -p /opt/coincync-source
     cd /opt/coincync-source
     git clone https://git.coincync.network/coincync/cync-protocol .
     ```
   - **scp the source from the operator's machine**:
     ```bash
     # From the operator's machine:
     rsync -av --exclude target/ --exclude .git/ \
       "/c/Users/unkno/OneDrive/coincync 1.0/" \
       root@<fuzz-box>:/opt/coincync-source/
     ```

   The `target/` directory is excluded — fuzzing builds its
   own. The `.git/` directory is optional; without it you
   can't pull updates in place but the fuzzer itself doesn't
   need it.

3. **Install the scripts**:

   ```bash
   # On the fuzz box, copy from the staged source:
   install -m 0755 /opt/coincync-source/scripts/coincync-fuzz.sh \
     /usr/local/bin/coincync-fuzz.sh
   install -m 0644 /opt/coincync-source/scripts/coincync-fuzz.service \
     /etc/systemd/system/coincync-fuzz.service
   ```

4. **Configure env**:

   ```bash
   cat > /etc/coincync/fuzz.env <<EOF
   FUZZ_REPO_DIR=/opt/coincync-source
   FUZZ_STATE_DIR=/var/lib/coincync/fuzz
   FUZZ_DURATION_SEC=1800
   FUZZ_JOBS=1
   EOF
   chmod 0644 /etc/coincync/fuzz.env

   mkdir -p /etc/coincync /var/lib/coincync/fuzz
   ```

   `FUZZ_DURATION_SEC=1800` (30 min per target per rotation)
   gives every target ~5 hours of fuzzing per day. Adjust
   based on how many targets you have and how aggressive
   you want to be.

5. **Discord webhook** (optional but strongly recommended):
   reuse the same setup as `coincync-selfcheck.sh`. The
   `DISCORD_WEBHOOK` should already live in
   `/etc/coincync/discord.env` (mode 0600 root-only).

6. **First build** (slow — 2-3 minutes per target the first
   time):

   ```bash
   cd /opt/coincync-source
   cargo +stable fuzz build --release
   ```

   Confirms all 5 targets compile before you start the
   continuous loop.

7. **Enable + start**:

   ```bash
   systemctl daemon-reload
   systemctl enable --now coincync-fuzz
   journalctl -u coincync-fuzz -f
   ```

   You should see `running target=fuzz_block for 1800s` and
   target rotation in the log.

### What you'll see in normal operation

```
[time] coincync-fuzz: running target=fuzz_block for 1800s
[time] coincync-fuzz: ok: fuzz_block finished with no new crashes
[time] coincync-fuzz: running target=fuzz_clsag for 1800s
[time] coincync-fuzz: ok: fuzz_clsag finished with no new crashes
... etc.
```

Every ~2.5 hours the loop completes one full rotation
through all 5 targets and starts again.

### What happens on a crash

1. libFuzzer writes the input that triggered the crash to
   `/var/lib/coincync/fuzz/<target>/crashes/<hash>`.
2. The script logs `CRASH found in <target>`.
3. Discord webhook fires with the last 60 lines of stdout.
4. The script continues to the next target (it doesn't
   stop on crash — you want to find more, not freeze on
   the first).

### Triaging a crash

```bash
# On the fuzz box:
ls /var/lib/coincync/fuzz/<target>/crashes/
# pick the most recent file:
ls -t /var/lib/coincync/fuzz/<target>/crashes/ | head -1

# Reproduce locally:
cd /opt/coincync-source
cargo +stable fuzz run --release <target> \
  /var/lib/coincync/fuzz/<target>/crashes/<filename>
```

The crash will reproduce deterministically. Examine the
panic message + backtrace. Fix in the source tree, commit,
mirror updates back to the fuzz box, restart the fuzz loop.

### Operational notes

- **CPU usage:** the fuzz process pegs one core at 100% for
  the duration. The systemd unit uses `Nice=10` so a
  colocated service (rig/node) preempts it under contention.
- **Disk usage:** the corpus grows over time; expect
  ~100MB-1GB per target after months of running. The
  `crashes/` dirs should stay small unless you're actually
  finding crashes.
- **Memory:** each libFuzzer process can spike to 2GB+ on
  pathological inputs. Unit caps at 4GB. If you see OOMs,
  reduce `FUZZ_JOBS=1`.
- **Updating the source:** pull or rsync the tree, then
  `systemctl restart coincync-fuzz`. The next rotation
  uses the new code.

---

## Path B — OSS-Fuzz (post-launch, when public repo exists)

OSS-Fuzz is Google's free continuous-fuzzing service for
open-source projects. They run your fuzz targets on their
infrastructure 24/7 — no fuzz box on your end at all.

### Eligibility

Per OSS-Fuzz's
[acceptance criteria](https://google.github.io/oss-fuzz/getting-started/accepting-new-projects/):

- ✅ Source code is open-source (publicly accessible).
- ✅ The project has a "noticeable" user base (you'll get
  there post-launch).
- ✅ At least 2 maintainers.

For CoinCync today: only the first criterion is the
blocker. Once `git.coincync.network` is live and the source
is publicly browsable, you can apply.

### Apply procedure

1. **Fork the OSS-Fuzz repo** at <https://github.com/google/oss-fuzz>.

2. **Create `projects/coincync/project.yaml`**:

   ```yaml
   homepage: "https://coincync.network"
   primary_contact: "<your-email>"
   auto_ccs:
     - "<second-maintainer-email>"
   main_repo: "https://git.coincync.network/coincync/cync-protocol"
   language: rust
   sanitizers:
     - address
   fuzzing_engines:
     - libfuzzer
   help_url: "https://docs.coincync.network/security/continuous-fuzzing"
   builds_per_day: 4
   ```

3. **Create `projects/coincync/Dockerfile`**:

   ```dockerfile
   FROM gcr.io/oss-fuzz-base/base-builder-rust
   RUN apt-get update && apt-get install -y cmake clang lld pkg-config libssl-dev
   RUN git clone https://git.coincync.network/coincync/cync-protocol.git
   WORKDIR cync-protocol
   COPY build.sh $SRC/
   ```

4. **Create `projects/coincync/build.sh`**:

   ```bash
   #!/bin/bash
   cd $SRC/cync-protocol/fuzz
   cargo +nightly fuzz build --release
   for target in fuzz_block fuzz_clsag fuzz_p2p_message \
                  fuzz_stealth fuzz_transaction; do
       cp ../target/x86_64-unknown-linux-gnu/release/$target \
          $OUT/$target
   done
   ```

5. **Submit a PR** to google/oss-fuzz with these three
   files. OSS-Fuzz maintainers review (typically 1-2 weeks).

6. **Once approved**, OSS-Fuzz runs your fuzzers
   continuously. Crashes file issues to a designated email
   address (the `primary_contact` from `project.yaml`).
   Public bugs are disclosed after 90 days; private until
   patched. This is industry standard.

### Why both paths?

OSS-Fuzz runs on Google's hardware (much faster than your
VPS), with structured crash deduplication, with regression
detection across builds. It's strictly better than
self-hosted IF you can get accepted.

Self-hosted runs TODAY with no review delay. The corpus
you accumulate self-hosted is yours; you can transfer it
to OSS-Fuzz when you're accepted there. Running both for
a few months is ideal — independent failure modes catch
different bugs.

---

## Pre-launch / post-launch decision

**Now (pre-launch, repo not yet public):**
- Set up Path A on a dedicated VPS (~30 min + the actual
  setup time on the box).
- Run for 2-4 weeks before mainnet launch. Triage anything
  it finds.
- Expect to find ~0-3 real bugs in this window. Most fuzz
  hits are minor edge cases that the existing tests already
  cover.

**Post-launch (repo public, Forgejo live):**
- Apply to OSS-Fuzz. Wait 1-2 weeks for review.
- Once approved, OSS-Fuzz runs in addition to the
  self-hosted setup. Don't tear down the self-hosted side
  — it gives you a corpus you control.
- Document the security-disclosure email in the README so
  OSS-Fuzz contact info is public.

---

## Cost summary

| Path | Setup time | Ongoing cost | Maintenance |
|---|---|---|---|
| Self-hosted on existing seed box | 30 min | $0 (existing infra) | 0 (systemd handles restart) |
| Self-hosted on dedicated VPS | 45 min | ~$5/mo | check journal weekly |
| OSS-Fuzz | 1-2 weeks (PR + review) | $0 | respond to issues filed |

**Best value:** dedicated VPS for self-hosted now,
OSS-Fuzz layered on top once the repo is public.
