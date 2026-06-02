# CIP-016 — RandomX hashrate parity with xmrig

**Status:** Sketch (research track — NOT on any committed release)
**Created:** 2026-06-02
**Replaces:** none
**Depends on:** v1.0 base chain mainnet stable in production

---

## Abstract

`coincync-rig` (our reference RandomX miner) currently runs at
~20-25% of xmrig's hashrate on the same hardware. On the testnet
this manifests as roughly a 4-5× per-thread gap (observed 2026-06-01
by community operator barns1253: ~9 KH/s on coincync-rig vs
~40 KH/s on xmrig, same CPU). Closing this gap matters because:

1. Operator experience: a privacy-coin miner that runs at 25% of the
   competitive baseline reads as "amateur project" to the broader
   RandomX mining community we want to attract.
2. Network hashrate: 4-5× more aggregate work per honest miner
   means correspondingly stronger 51%-attack defense.
3. Strategic narrative: "use our reference miner, it's competitive
   with xmrig" is a cleaner story than "use xmrig with our pool
   protocol shim."

This CIP scopes the **research track** to characterize and close
the gap. It explicitly does NOT commit to a fix timeline — the gap
may turn out to require a multi-month engineering investment, or
may resolve via a randomx-rs library upgrade. We commit only to
**measuring** the gap on tracked CPUs and capturing the findings.

This is a v2.0+ research item, NOT v1.0.x or v1.1 work. The base
chain mainnet (v1.0) and cyncswap (v1.1) must ship cleanly before
optimization research gets engineering attention.

---

## Background — what was already done

**RandomX Phase 2** (shared dataset + per-thread VMs) was shipped
in `src/consensus/pow.rs:296-332` on 2026-05-25. That refactor
killed the `Mutex<RandomXVM>` bottleneck that previously serialized
all hash dispatches through a single VM. Post-refactor, aggregate
hashrate scales linearly with `--threads`. So the "Phase 2
uncommitted" line on the v1.0.10 checklist was outdated — the
work was already done; only the v2.0+ xmrig-parity question
remains.

Empirically post-Phase-2:
- 16-thread mining on a desktop Intel i7: ~1700-2000 H/s
  (~106-125 H/s per thread)
- 2-thread mining on a Vultr 2-vCPU box: ~929 H/s
  (~465 H/s per thread — different hardware tier)

xmrig on the same desktop: ~40 KH/s with 16 threads (~2500 H/s per
thread). So per-thread we're at roughly 5-25% of xmrig depending on
CPU tier. The 16-thread desktop case is the worst — 5%-ish — which
suggests xmrig is using CPU features we aren't.

---

## What's probably wrong

The Phase 2 refactor proved the dispatch path isn't the bottleneck.
What's left is **inside** the per-hash work. xmrig's competitive
advantages over a naive `randomx-rs` binding include:

1. **JIT codegen variants tuned per microarchitecture.** xmrig has
   separate code paths for Intel Haswell, Skylake, Zen 2, Zen 3,
   etc. with hand-tuned register allocation. `randomx-rs` (and
   therefore `coincync-rig`) uses upstream RandomX's generic
   path, which leaves cycles on the table on every CPU.

2. **Cache line + prefetch patterns.** RandomX's scratchpad is
   2 MB per VM; xmrig issues software prefetches one iteration
   ahead so the next 64B line is in L1 by the time it's read.
   Our path doesn't issue any prefetches.

3. **MSR tweaks** (Linux only). xmrig writes specific MSRs on
   AMD Zen CPUs to disable certain frequency/cache features that
   hurt RandomX throughput specifically. Requires root + carries
   small system stability risk.

4. **NUMA topology awareness.** On multi-socket servers, xmrig pins
   threads to NUMA nodes that have the dataset locally allocated.
   `randomx-rs` doesn't expose dataset placement, so we can't
   easily mirror this.

5. **Hugepages.** xmrig allocates the 2 GB dataset on 2 MB hugepages
   when available (Linux: `vm.nr_hugepages` sysctl + capability or
   root; Windows: SeLockMemoryPrivilege). This cuts TLB pressure
   significantly during VM execution. `randomx-rs` may or may not
   forward this option through to the underlying RandomX library
   — needs verification.

Items (1), (3), (4) are unlikely to be closable without significant
binding work or going off `randomx-rs` to a custom FFI binding.
Items (2) and (5) are tractable inside the existing library if
upstream randomx-rs exposes the right knobs.

---

## Specification — what this CIP actually commits to

**Phase A — Measurement (v1.0.x window).** Build a reproducible
benchmark harness that:

- Runs both `coincync-rig run-solo --threads N` and `xmrig
  --threads N --no-color` against the same RandomX seed for the
  same wall-clock duration (10 min recommended for noise floor).
- Captures: total hashes, H/s, per-thread H/s, CPU model, kernel,
  hugepage status, frequency scaling governor.
- Outputs a CSV row appended to a tracked file
  `docs/perf/randomx-parity-vs-xmrig.csv`.

This phase commits to QUANTIFYING the gap on the CPUs our operators
actually use. The CSV file becomes the source of truth for "how
much slower are we" and lets us track whether subsequent changes
help or hurt.

Lives in `scripts/bench-randomx-vs-xmrig.sh`. Single shell script,
no Rust changes.

**Phase B — Hugepages support (v2.0 candidate).** If randomx-rs
exposes hugepage flags (need to verify in v1.4+ binding), wire them
through with an opt-in CLI flag `--hugepages`. Operator-side
hugepage allocation stays manual (sysctl + capability), but the
miner can use them if available.

Expected gain: 10-30% on Linux with proper hugepage setup.

**Phase C — Prefetch instrumentation (v2.0 candidate, big).**
Investigate whether randomx-rs lets us inject prefetch hints from
the calling code, or whether the prefetch logic has to live inside
the upstream RandomX C++. If the former: tractable. If the latter:
significant upstream contribution work.

**Phase D — Custom FFI binding (v3.0+ research).** If Phases B/C
land us within 50% of xmrig and the remaining gap matters for
network security, consider forking randomx-rs to expose the JIT
codegen variants. Significant unsafe-Rust expertise required.
This is research, not a commitment.

---

## Out of scope (explicit non-goals)

- **No consensus changes.** RandomX as the PoW function is fixed;
  this CIP is purely about miner-side speed.
- **No pool protocol.** Solo mining is the reference flow; pool
  support is a separate CIP if it ever happens.
- **No GPU or ASIC paths.** RandomX is CPU-only by design (Article
  IX-adjacent positioning); this CIP doesn't relitigate that.
- **No xmrig integration.** We don't ship xmrig under our binary
  name. The narrative cost is too high.

---

## Why this is research, not roadmap

Closing the xmrig gap is **bounded-difficulty work with unbounded
calendar risk**. Each phase above (especially Phase C, D) could
take 2 weeks or 2 quarters depending on what `randomx-rs` does or
doesn't expose. Locking it to a release schedule would either
artificially constrain the work or slip the release.

Better posture: maintain it as a tracked Sketch CIP with
quantified-progress checkpoints in `docs/perf/randomx-parity-vs-
xmrig.csv`. Promotion to Draft (and a real release commitment)
happens when one of the phases above has a tractable scope + ready
code.

---

**Last updated:** 2026-06-02
**Author:** Sebastian (ghostrider1092)
**Review status:** Sketch — research track, not committed to any release.
