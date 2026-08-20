# Contributing to CoinCync

**Privacy money that requires no permission.** That's the promise. Every contribution is evaluated against whether it keeps that promise intact.

CoinCync is a privacy-first proof-of-work payments coin governed by an explicit Constitution. This document tells you how to ship code, where bugs go, what we'll accept, and what we won't.

If you're scanning: skip to **Quick Start** below.

---

## TL;DR

- **Welcome:** privacy improvements, performance optimizations, UX polish, wallet work, network-stack improvements, audit fixes, documentation, test coverage.
- **Out of scope:** see [docs/explicitly-not-doing.md](docs/explicitly-not-doing.md) for the canonical "we will not add this" list. Quick summary: stablecoins, smart-contract VMs, cross-chain bridges beyond cyncswap/CyncHub, NFTs / name services, governance tokens, admin keys, fee redirects, KYC integration. Asking again in 6 months will get the same answer.
- **Pseudonymous participation is a Right** (Right V). Use whatever name you want.
- **Security bugs:** email `CyncLabs@proton.me` with a PGP-encrypted message. Do not open a public issue. See [SECURITY.md](SECURITY.md).
- **Roadmap commitments:** only what's in [docs/roadmap.md](docs/roadmap.md) is committed. CIPs marked `Sketch` are research, not commitments — see [docs/cip/README.md](docs/cip/README.md) for the legend.
- **Everything else:** open a PR.

---

## Quick Start

```bash
git clone <repo-url>
cd coincync
cargo build --release
cargo test --release
```

Tests must pass before you submit a PR. Local builds use the same `critical_files.lock` integrity check the fleet builds use — if you modify a consensus-critical file by accident, the build will fail with a clear `UNCONSTITUTIONAL: Article X` error pointing at the violation.

Branch off `main`, write your change, run tests, open a PR. Maintainers review in rough chronological order.

---

## What We Welcome

If your contribution falls into one of these categories, you don't need pre-approval — just open a PR:

- **Privacy improvements.** Stronger ring sizes, better stealth-address handling, encrypted memo improvements, traffic-shaping refinements.
- **Cryptographic modernization.** Per Right XV, primitives may be upgraded to strictly stronger successor schemes. Bulletproofs+ is our current range proof; if you have a Bulletproofs++ implementation that demonstrably strengthens the protection, we want to see it.
- **Performance optimizations.** Anywhere — node, wallet, miner, RPC.
- **Network-stack work.** Peer scoring, Dandelion++ refinements, framing, sync. *Note: these touch consensus-adjacent paths; expect closer review.*
- **Wallet UX.** Tauri wallet, CLI wallet, mobile, hardware-wallet integration.
- **Documentation.** README, CONTRIBUTING (this file), CONSTITUTIONAL_COMMENTARY, mdbook, code comments.
- **Test coverage.** Especially for cryptographic primitives, fee distribution, emission curve, ring-signature verification.
- **Audit-driven fixes.** Anything from a third-party security review.
- **Atomic-swap implementation.** The `crates/coincync-swap/` skeleton has clear stages laid out in CIP-001. Each stage is a viable contribution unit.

---

## What We Will Not Accept

Some contributions are categorically out of scope. The Constitution forbids these mechanisms at the protocol level — proposing them is not a path to merge regardless of how the proposal is framed:

- **Stablecoin issuance** (Article XI — No Algorithmic Capture)
- **Yield products, staking rewards, lending facilities** (Article XII — No Admin Authority; Article XI)
- **Cross-chain bridges accepting external state into consensus** (Article XIII — No External Trust). *Atomic swaps are the allowed path; they don't admit external state into consensus.*
- **Smart-contract execution layers, NFT primitives, name services, identity attestations** (Article XIV — No Surveillance Layer)
- **Admin keys, pause / freeze / seize functions, emergency overrides** (Article XII)
- **Fee redirects to any party other than miner + burn** (Article II, Article XVI, Right XIV)
- **PoW algorithm changes away from RandomX** (Article V)
- **Pre-mine, dev tax, foundation treasury** (Article II)

If you genuinely think one of these would help users, the Constitution's Article XV "Spirit and Construction" requires you to demonstrate that the change *strengthens* a specific user protection without weakening any other. The bar is high; the path exists. Most proposals do not clear it.

---

## CIP Process — For Protocol Changes

Any change that affects consensus rules, network protocol, transaction format, or the cryptographic primitives in Right I requires a **CoinCync Improvement Proposal**. See `docs/cip/CIP-001-atomic-swap.md` for the format.

1. Open a draft CIP at `docs/cip/CIP-NNN-short-name.md`. Status: Draft.
2. Discuss publicly (Discord, GitHub issue, the CIP itself) for **at least 60 days** before final.
3. Working reference implementation in a feature branch.
4. Audit / cryptographic review for changes touching the privacy stack.
5. Hard-fork activation requires 95% miner version-bit signaling.

Non-consensus changes (wallet, RPC additions that aren't consensus-affecting, performance, docs) can ship without a CIP.

---

## Pseudonymous Participation

You may contribute under a pseudonym. You are not required to verify your identity to submit code, file bugs, propose CIPs, or hold any community role. This is Right V of the Bill of Rights and is not negotiable.

## Signed commits (required)

Branch protection on `main` requires every commit to carry a verified signature. PRs with unsigned commits will be blocked by GitHub before review. You may sign with **either SSH or GPG** — we don't care which, and we don't care whose real name (if any) maps to the key.

**SSH signing (easier, no extra tooling):**

```bash
git config --global gpg.format ssh
git config --global user.signingkey <path-to-your-ssh-pubkey>      # e.g. ~/.ssh/id_ed25519.pub
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Then add the **public key** at [github.com/settings/ssh/new](https://github.com/settings/ssh/new) with **Key type = Signing Key** (this is a separate slot from Authentication; missing this step is the most common cause of commits showing as "unverified" despite local signing working). See GitHub's [SSH commit signature verification guide](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification#ssh-commit-signature-verification) for the full reference.

**GPG signing (traditional):**

Follow GitHub's [generating a GPG key](https://docs.github.com/en/authentication/managing-commit-signature-verification/generating-a-new-gpg-key) guide, then upload the public key under **GPG keys** in the same settings page.

Verify with `git log --show-signature` locally and the green "Verified" badge on github.com after pushing.

---

## Code Style + Tests

- **Rust 2021 edition.** Format with `cargo fmt`, lint with `cargo clippy --all-targets`.
- **No `unsafe` without justification.** If you genuinely need `unsafe`, prefix the block with a `// SAFETY:` comment explaining the invariant you're upholding.
- **No `unwrap()` / `expect()` in production code paths.** Use `?` or proper error handling. Tests are exempt; the operative code is not.
- **Comments explain *why*, not *what*.** The code already shows what; comments document the reason future-you will need.
- **Security-relevant code gets a `// SECURITY:` prefix** so reviewers and auditors can grep for it.
- **Tests are required for behaviour changes.** A bug fix without a regression test is incomplete. Cryptographic primitives need known-answer tests; consensus-affecting code needs deterministic test vectors.
- **No external network calls in tests.** Tests must run offline.
- **Reproducible builds.** Per Right XIII, releases must be reproducible from public source. Don't introduce build-time non-determinism (timestamps, random tokens) without a clear reason.

---

## Consensus-Critical Changes

Changes to files in `critical_files.lock` (Constitution, Bill of Rights, `src/constants.rs`, consensus modules, emission curve, etc.) require:

1. **Refresh the lockfile.** After careful review, run `COINCYNC_REGEN_LOCK=1 cargo run --locked --bin update-critical-hashes` (or set `COINCYNC_REGEN_LOCK=1` in your PowerShell session first). Commit the updated `critical_files.lock` alongside the code change.
2. **Update protocol documentation** if the change is user-visible.
3. **Add regression tests** that fail without the change and pass with it.
4. **Maintainer review.** Two-of-N maintainer sign-offs for anything touching consensus rules; one for anything else in the lockfile (docs, constants).
5. **CIP if it affects users.** Internal refactors may not need a CIP; user-visible behavior changes do.

---

## Where Bugs Go

| Type | Where |
| --- | --- |
| **Security vulnerability** (consensus, crypto, privacy break, supply integrity) | `CyncLabs@proton.me` with PGP-encrypted message. Public PGP key in `SECURITY.md`. **Never open a public issue.** |
| **Non-security bug** | GitHub Issues |
| **Question / setup help** | [Discord](https://discord.gg/5tYNSCsqzy) — `#help` channel |
| **CIP discussion** | The CIP file itself + [Discord](https://discord.gg/5tYNSCsqzy) `#cip-discussion` |

The 90-day coordinated-disclosure window for security issues is committed in Article XV of the Constitution. We will respond to security reports within 7 days; we will publish a fix or coordinated-disclosure plan within 90 days.

---

## Code of Conduct

The community standards live at [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). Be civil. Disagreement is fine; harassment is not. Pseudonymous participants get the same treatment as named ones.

---

## License

By contributing, you agree your contribution is released under the project's MIT license. The MIT license disclaims warranty in all jurisdictions where such disclaimers are recognized — see Article XIX of the Constitution and the parallel "Note on Properties, Not Promises" in the Bill of Rights.

---

## Quick Reference

- **Constitution:** [`CONSTITUTION.md`](CONSTITUTION.md)
- **Bill of Rights:** [`docs/BILL_OF_RIGHTS.md`](docs/BILL_OF_RIGHTS.md)
- **Constitutional Commentary** (rationale, no constitutional force): [`docs/CONSTITUTIONAL_COMMENTARY.md`](docs/CONSTITUTIONAL_COMMENTARY.md)
- **CIP index:** [`docs/cip/`](docs/cip/)
- **Critical files lockfile:** [`critical_files.lock`](critical_files.lock)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- **Maintainers:** [`MAINTAINERS.md`](MAINTAINERS.md) — who reviews what, review SLAs, recruiting
- **Bus-factor inventory:** [`docs/governance/bus-factor.md`](docs/governance/bus-factor.md) — single-point-of-failure map
- **Maintainer recovery procedure:** [`docs/operations/MAINTAINER_RECOVERY.md`](docs/operations/MAINTAINER_RECOVERY.md) — if the primary is gone
