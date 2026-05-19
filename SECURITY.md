# Security policy

**Privacy money that requires no permission.** That promise is what
makes security disclosure load-bearing for CoinCync: bugs in this
codebase can lead to direct financial loss, deanonymization of users,
or chain forks. Disclosure handled responsibly is the difference
between "we fixed a bug before anyone noticed" and "users lost money."

This document tells you how to report a vulnerability, what to expect
in response, and what protections we extend to good-faith researchers.

## See also

- [docs/cyncswap-user-safety.md](docs/cyncswap-user-safety.md) — the
  6-layer user-safety stack that bounds principal-loss risk in the
  cyncswap atomic-swap and CyncHub orderbook surfaces (V1 cap: $500
  per swap).
- [docs/explicitly-not-doing.md](docs/explicitly-not-doing.md) — the
  features CoinCync will not add, which constrain what bugs are even
  possible (e.g., no smart-contract VM means no reentrancy bug class).
- [docs/decisions/](docs/decisions/) — recorded design decisions that
  affect the security perimeter.

## Reporting a vulnerability

**Email:** `security@coincync.network`

If you believe you have found a security issue, send the report to
that address. The mailbox is monitored daily.

For the highest-severity issues (fund-loss, key-recovery, chain-fork,
deanonymization), use the PGP key fingerprinted below to encrypt the
report. PGP-encrypting low-severity reports is welcome but not
required.

**PGP key:** _to be published in a `SECURITY-PGP.asc` file alongside
this document before public testnet announcement. Until that file
lands, plaintext email to `security@coincync.network` is acceptable
and will be triaged the same day._

## What to include

A useful report typically contains:

- **A clear description of the issue** — what's the bug, what's the
  bad outcome, what assumption is being violated.
- **Reproduction steps** — minimal code or commands that demonstrate
  the issue. If it depends on a specific commit, include the hash.
- **Impact assessment** — what could an attacker achieve? Affected
  components? User-visible consequences?
- **Suggested mitigation** if you have one. Optional but appreciated.

If you can't share full details (e.g., you're constrained by your
employer's disclosure policy), a brief acknowledgment that you have
information you can't share yet is still useful. We'll coordinate.

## What to expect

| Window | Action |
|---|---|
| **Within 24 hours** | We acknowledge receipt and confirm whether the issue is reproducible on our end. |
| **Within 7 days** | We classify severity (critical / high / medium / low) and confirm the disclosure timeline. |
| **Within 30 days** | For critical and high issues: a fix is in development or already deployed. For medium and low: triaged into the next release window. |
| **Within 90 days** | The issue is fixed and disclosed publicly, OR we've requested an extension with reasoning. |

We commit to public credit (your name, handle, or anonymous — your
choice) when the fix lands, unless you explicitly ask for none.

## Disclosure policy

CoinCync follows a **90-day coordinated disclosure** model. We will:

- Work with you to confirm the issue and develop a fix.
- Privately distribute the fix to operators of the testnet fleet,
  major exchange listings (when those exist post-mainnet), and major
  wallet integrations before public disclosure.
- Publicly disclose the issue and fix together, with credit to the
  reporter.
- Not threaten legal action, restrain your ability to discuss your
  findings (subject to embargo until disclosure), or claim ownership
  of your research.

If the 90-day window is insufficient (rare; usually means the fix
requires a hard-fork that needs activation lead time), we'll explain
why and propose an extension. You have the final say on whether to
disclose at the original deadline.

## Safe harbor

We will not pursue civil or criminal action against researchers who:

- Make a good-faith effort to comply with this policy.
- Avoid privacy violations (don't access more user data than needed
  to demonstrate the issue).
- Avoid destruction of data or interruption of service beyond what's
  necessary to demonstrate the issue.
- Give us reasonable time to respond before public disclosure.
- Do not perform attacks against any production system on behalf of
  someone else (i.e., don't get hired by a third party to attack us
  through this program — direct relationship only).

You're welcome to test against the public testnet and the fleet
infrastructure listed at the bottom of this document. **Mainnet
testing requires explicit written permission** until the network is
live and a public bug-bounty program is announced.

## Out of scope

These don't qualify under this policy:

- **Social engineering** of CoinCync contributors or community members.
- **Physical attacks** against fleet infrastructure or contributors.
- **DoS / volumetric attacks** against the public services. Rate
  limits, peer scoring, and bandwidth are tested under load by the
  team's own soak runs; flooding the testnet to demonstrate "you
  can flood the testnet" is not in scope.
- **Vulnerabilities in third-party libraries** that have not been
  modified (e.g., `curve25519-dalek`, `argon2`). Report those
  upstream; we'll mirror the fix once it lands.
- **Best-practice deviations** that aren't actually exploitable
  (e.g., "you're not using TLS 1.3 on this endpoint" without a
  concrete attack scenario).
- **Issues already documented** in `docs/launch/KNOWN_ISSUES.md` or
  fixed in a commit on `main` — but please confirm before assuming.

## Bug bounty

CoinCync does not have a paid bug-bounty program at the time of this
document's first publication. Pre-mainnet, the project's funding
model does not support cash bounties.

We will introduce a paid bounty program **after mainnet launch** once
the network has economic value to defend. The structure will be
announced at that time.

In the meantime, we offer:

- **Public credit** at fix-disclosure time.
- **An entry on the Hall of Fame** at
  `https://coincync.network/security/credits` (post-launch).
- **A signed letter of acknowledgement** for your portfolio if
  requested.

## Public testnet infrastructure (in-scope for testing)

These hosts are operated by the project and are explicit testbeds.
You may test them within the limits of this policy:

- `seed1.coincync.network` (NJ, US)
- `seed2.coincync.network` (Amsterdam, NL)
- `seed3.coincync.network` (Tokyo, JP)
- `explorer.coincync.network` (Dallas, US)
- `api.coincync.network` (Frankfurt, DE)

Please do not perform sustained DoS, attempt to compromise the host
operating systems, or pivot from these systems to anything else.

## Pre-disclosure communication channel

If you would like to discuss a potential vulnerability before
sending a formal report (e.g., to confirm scope, ask about
methodology, or request the PGP key out of band), the best initial
contact is `security@coincync.network` itself with a subject line
like `[QUESTION] re: <topic>`. We'll route appropriately.

For genuine emergencies (e.g., active exploitation observed),
include `[URGENT]` in the subject line.

## This document

The version of this document at the time of public testnet launch
(2026-05-11) is the canonical statement. If we update it, we will
maintain a `CHANGELOG` section at the bottom. Material changes
(disclosure window, scope, safe harbor) will be announced via the
project's official channels at least 30 days before they take
effect.

---

_Last updated: 2026-05-08._
