# CoinCync — Canonical Project Facts

Single source of truth for the numbers, hashes, and identifiers used
across listing submissions, exchange paperwork, audit-firm intake
forms, and compliance disclosures. When a fact changes here, update
[SUBMISSION_KIT.md](SUBMISSION_KIT.md) and any external listing in
the same change.

Every claim below is backed by an in-repo file at a path you can
hand to a reviewer to verify. Reviewers love that — guessable
numbers without sources are a scam signal.

---

## 1. Identity

| Field | Value | Source |
|---|---|---|
| Name | CoinCync | repository root |
| Ticker | CYNC | [src/constants.rs:173](../../src/constants.rs#L173) |
| Atomic unit divisor | 1,000,000,000,000 (12 decimals) | [src/constants.rs:166](../../src/constants.rs#L166) |
| Genesis date (target) | 2026-10-01 | [docs/launch/GENESIS-CEREMONY-PLAN.md](../launch/GENESIS-CEREMONY-PLAN.md) |
| Network type | Layer-1, standalone | n/a |
| Consensus | Proof-of-Work (RandomX) | [src/consensus/pow.rs](../../src/consensus/pow.rs) |
| Block time (target) | 120 seconds | [src/constants.rs:35](../../src/constants.rs#L35) |
| Difficulty algorithm | ASERT-DAA (3600s halflife) | [src/constants.rs:62](../../src/constants.rs#L62), [src/consensus/difficulty.rs](../../src/consensus/difficulty.rs) |
| Max block size | 2 MiB | [src/constants.rs:49](../../src/constants.rs#L49) |
| Max txs per block | 5,000 | [src/constants.rs:52](../../src/constants.rs#L52) |
| Default mainnet P2P port | 19080 | [src/constants.rs:106](../../src/constants.rs#L106) |
| Default mainnet RPC port | 19081 | [src/constants.rs:109](../../src/constants.rs#L109) |
| Protocol version | 2 | [src/constants.rs:32](../../src/constants.rs#L32) |

## 2. Supply & emission

| Field | Value | Source |
|---|---|---|
| Total supply cap | 100,000,000 CYNC (asymptotic, never reached) | [src/constants.rs:774](../../src/constants.rs#L774), Constitution Article I |
| Genesis premine | **0 CYNC** | enforced by absence of premine code; reviewer can verify by reading `src/emission/curve.rs` and `src/genesis.rs` |
| Developer tax | **0% (compile-time enforced)** | `DEV_TAX_PERCENT = 0` at [src/constants.rs:810](../../src/constants.rs#L810); Article II compile assertion at line 811 |
| Foundation reserve | **None** | no foundation entity exists; see §6 |
| Initial block reward | 50 CYNC | derived from `EMISSION_DIVISOR = 2_000_000` |
| Emission curve | Smooth asymptotic (no halvings, no eras) | [src/constants.rs:776-786](../../src/constants.rs#L776-L786) |
| Tail emission | 0.6 CYNC/block (forever, after curve falls below) | [src/constants.rs:803](../../src/constants.rs#L803) |
| Fee burn | 30% of fees burned per block | (verify against [src/emission/curve.rs](../../src/emission/curve.rs)) |
| Self-reported circulating supply URL | (post-launch — see SUBMISSION_KIT.md §3) | n/a |

**Reviewer verification path** for the "no premine, no dev tax"
claim:

```bash
# Article II is compile-time asserted. Building the binary proves
# the claim — any non-zero dev tax fails to compile.
grep -n "DEV_TAX_PERCENT" src/constants.rs
grep -n "Article II" src/constants.rs
cargo check  # build succeeds == DEV_TAX_PERCENT is 0
```

## 3. Privacy stack (for technical reviewers)

| Component | Construction | Notes |
|---|---|---|
| Sender anonymity | CLSAG ring signatures, min ring size **11** | Monero-school floor; compile-asserted in Article III |
| Amount hiding | Pedersen commitments + range proofs (Bulletproofs+) | every non-coinbase output |
| Recipient hiding | Stealth one-time addresses | per Article III |
| Optional shielded pool (v1.2) | Orchard (Halo 2 proofs) | [docs/cip/CIP-013-phase-2-orchard-shielded-pool.md](../cip/CIP-013-phase-2-orchard-shielded-pool.md) (post-base-chain) |
| View keys | Public-side observable; sharing reveals full RX history | per Monero convention |

## 4. Distribution

CoinCync is a **fair-launch proof-of-work coin**. Distribution
mechanism: **mining only**, starting from genesis block 0 at the
public genesis time. No ICO, no IDO, no airdrop, no private sale,
no team allocation, no investor allocation.

Pool-mineability: yes. P2Pool integration documented at
[docs/P2POOL_INTEGRATION.md](../P2POOL_INTEGRATION.md).

Solo-mineability: yes. Reference miner shipped in the node binary.

## 5. Source & verification

| Field | Value |
|---|---|
| Primary repository | (set the public URL before submission — likely github.com/...) |
| License | (verify — likely MIT or Apache-2.0; see `LICENSE`) |
| Language | Rust (toolchain pinned to 1.88.0 via `rust-toolchain.toml`) |
| Reproducible build | yes — [scripts/verify-reproducible-build.ps1](../../scripts/verify-reproducible-build.ps1) |
| Critical-files integrity | SHA-256 lockfile at [critical_files.lock](../../critical_files.lock); enforced in `build.rs` |
| Signed binaries | yes — SSH-signed commits + signed SHA256SUMS (see [docs/launch/v1.0.10-CHECKLIST.md](../launch/v1.0.10-CHECKLIST.md)) |
| Fuzz suite | 27 cargo-fuzz targets in [fuzz/fuzz_targets/](../../fuzz/fuzz_targets/) |
| Constitutional guards | compile-time assertions in [src/constants.rs:788+](../../src/constants.rs#L788) bind the binary to [CONSTITUTION.md](../../CONSTITUTION.md) |

## 6. Team / legal entity

| Field | Value |
|---|---|
| Legal entity | **None.** CoinCync is a decentralized protocol with no operating company. See [docs/DISCLAIMER.md](../DISCLAIMER.md) §1. |
| Maintainers | listed in [MAINTAINERS.md](../../MAINTAINERS.md) (root) |
| Bus factor | tracked in [docs/governance/bus-factor.md](../governance/bus-factor.md) |
| Contact email (general) | (set this — recommend `contact@coincync.network`) |
| Security contact | `CyncLabs@proton.me` ([SECURITY.md](../../SECURITY.md)) |
| Abuse / takedown contact | (set this — recommend `abuse@coincync.network`) |
| Press / partnerships | (set this — recommend `press@coincync.network` or reuse `contact@`) |

## 7. Public infrastructure

| Host | Role | Region |
|---|---|---|
| seed1.coincync.network | P2P seed | NJ, US |
| seed2.coincync.network | P2P seed | Amsterdam, NL |
| seed3.coincync.network | P2P seed | Tokyo, JP |
| explorer.coincync.network | Block explorer | Dallas, US |
| api.coincync.network | Public RPC | Frankfurt, DE |

(Mirror at `.org` TLD via Cloudflare for resilience.)

## 8. Audit posture

| Field | Value |
|---|---|
| External audit status | (fill in once a firm is booked — booked / in-progress / report-URL) |
| Internal pre-audit prep | [docs/audit-submission.md](../audit-submission.md), [docs/security/](../security/) |
| Threat model | [docs/THREAT_MODEL.md](../THREAT_MODEL.md) |
| Known issues | [docs/launch/KNOWN_ISSUES.md](../launch/KNOWN_ISSUES.md) |
| Bug bounty program | (fill in — currently "post-mainnet, public credit only" per [SECURITY.md](../../SECURITY.md) §Bug bounty) |

## 9. Social

| Platform | Handle / URL |
|---|---|
| Website (primary) | https://coincync.network |
| Website (mirror) | https://coincync.org |
| Discord | (set the invite URL) |
| Twitter / X | (set the handle, if any) |
| Reddit | (set the subreddit, if any) |
| GitHub | (set the org URL) |

---

**Last updated:** 2026-05-26
**Next required update:** before mainnet tag-cut. Fill in every
parenthesized "(set this)" placeholder. Re-verify every line in §1
and §2 against the in-tree source paths.
