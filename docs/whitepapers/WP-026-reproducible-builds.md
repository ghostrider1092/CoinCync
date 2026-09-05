# WP-026 · Reproducible Builds and Release Attestation
### Closing the gap between the source people review and the binary people run

**Status:** Shipped · **Layer:** Build / Release · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Every other paper in this series argues about source code. Users do not run source
code.

Between the reviewed repository and the binary on an operator's machine sits a
build, and that build is the single least-scrutinised step in the whole chain of
trust. A backdoor inserted there is invisible to source review, invisible to
audits, and invisible to the maintainer if their machine is the compromised part.
For a privacy chain — where the binary holds spend keys and decides what to leak
to the network — that gap is unacceptable.

Reproducible builds close it by making the claim **checkable by anyone**: build
the same commit yourself, and get the same bytes. If you do not, something is
wrong, and you find out without needing to trust anyone's word.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Backdoored release binary** | Users cannot check the binary against the source | Anyone can rebuild the same commit and diff the bytes |
| **Compromised maintainer machine** | The build environment is trustworthy because the maintainer is | The build runs in a pinned container, and any third party can reproduce it |
| **Substituted release artifact** | A download is what it claims to be | Signed release manifest, verified before comparison |
| **Toolchain drift** — a different compiler quietly produces different behaviour | "Same source" implies "same binary" | Pinned Rust toolchain and pinned base image |
| **Silent dependency substitution** | Dependency resolution is deterministic | `Cargo.lock` committed and used |

---

## 3. Design

### 3.1 A pinned, containerised build

Release binaries are built inside Docker from a **pinned base image** and a
**pinned Rust toolchain**, with `Cargo.lock` committed so dependency resolution is
fixed. The container removes the operator's machine from the equation: the build
depends on the image and the commit, not on what happens to be installed locally.

The build is scripted (`scripts/build-in-docker.sh`) rather than documented as a
procedure, because a procedure is something people vary and a script is something
they run.

### 3.2 The verification path

`scripts/verify-build.sh <version>` performs the whole check end to end:

1. Download the published release manifest and its signature.
2. **Verify the signature** against the project release key.
3. Build the same git commit locally, inside the pinned Docker image.
4. **Diff** the locally-built binaries against the released ones.
5. Print PASS or FAIL with details.

Exit codes distinguish the outcomes that call for different responses — a build
error, a signature failure, and a **binary mismatch** (`3` — "investigate
immediately") are not the same event, and collapsing them into non-zero would
throw away the distinction that matters most. This is the same three-valued
reasoning as WP-013 §3.5 and WP-017 §3.6: a verification tool must separate "I
could not check" from "the check failed."

### 3.3 What the tooling says it does not do

The script documents its own limits in its header, which is a design choice worth
copying:

- It does **not verify the source tree itself.** Audits, tests, and review do that.
  Reproducibility proves the binary matches the source; it says nothing about
  whether the source is good.
- It does **not tell you to trust the project release key blindly.** The key
  fingerprint must be verified **out of band** before the signature check means
  anything. A signature verified against a key you got from the same place as the
  binary proves nothing.
- It does **not detect runtime backdoors present in the source tree.** Those
  reproduce perfectly. They are an audit problem, not a reproducibility problem.

A verification tool that overstates its coverage is worse than one that does less,
because operators calibrate their trust to what they believe was checked.

### 3.4 Where this sits in the trust chain

Three separate controls cover three separate questions, and none substitutes for
another:

| Question | Control |
|---|---|
| Does the source match what was agreed? | Critical-files hash lock (WP-007) |
| Does the binary match the source? | **This paper** |
| Does the chain state match the network? | Snapshot checkpoint binding (WP-024) |

WP-024's security argument reduces to trusting the checkpoints compiled into the
binary. This paper is what makes that reduction sound: without reproducibility,
"the binary's checkpoints" is a phrase with no verifiable content.

### 3.5 Release discipline

The `Cargo.toml` version must be bumped to match the release tag **before**
tagging. The `check-update` subcommand depends on it, and binaries otherwise
misreport their own version — a small thing that undermines every operator's
ability to know what they are running, which is the whole point of this paper.

---

## 4. Security analysis

**What holds.** A released binary's provenance is independently checkable by any
third party with Docker and the repository, without trusting the maintainer, the
build machine, or the download host.

**What this does not protect against.**

- **A malicious source tree** (§3.3). This is the important one: reproducibility
  and source integrity are orthogonal, and reproducibility is the *easier* of the
  two.
- **A compromised release key**, unless the fingerprint was verified out of band.
- **A compromised base image.** Pinning by tag is weaker than pinning by digest;
  pinning by digest still trusts the registry.
- **Dependency source compromise.** `Cargo.lock` pins versions and hashes, which
  makes substitution detectable, but a malicious upstream release reproduces
  deterministically like anything else.
- **Operators who do not verify.** A reproducible build nobody reproduces provides
  no protection. The value is realised only when someone actually runs the check —
  which argues for independent rebuilders, not just the capability.
- **CI does not currently run this.** GitHub Actions is blocked at the account
  level for this project (no workflow run has ever completed), so verification is
  a manual step rather than a gate on every release. This is an operational gap
  outside the code's control and it is the largest practical weakness here.

---

## 5. Implementation

| Component | Location |
|---|---|
| Pinned build image | `Dockerfile` |
| Containerised build | `scripts/build-in-docker.sh` |
| End-to-end verification | `scripts/verify-build.sh` |
| Windows verification | `scripts/verify-reproducible-build.ps1` |
| Dependency pinning | `Cargo.lock` |
| Source integrity gate | `build.rs`, `critical_files.lock` (WP-007) |
| Swap-crate reproducibility vectors | `crates/coincync-swap/test-vectors/reproducibility/` |

---

## 6. Known limits

- Not enforced in CI (§4) — the biggest practical gap.
- Base image pinned by tag rather than digest.
- Reproducibility says nothing about source quality.
- Verification depends on out-of-band key-fingerprint distribution, which has no
  automated path today.
- No independent third-party rebuilder exists yet; the check is currently only
  ever run by us.

---

## 7. References

- The Reproducible Builds project — definitions, tooling, and the argument for
  independent rebuilders.
- Thompson (1984), *Reflections on Trusting Trust* — why the compiler step is the
  one you cannot review your way out of.
- Internal: [WP-007 Hash lock](WP-007-critical-files-hash-lock.md),
  [WP-024 Snapshot bootstrap](WP-024-snapshot-bootstrap.md),
  `docs/AUDIT_READINESS.md`.
