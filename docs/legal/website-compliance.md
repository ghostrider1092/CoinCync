# CoinCync Website — Compliance Page

This is the source draft for the legal / compliance content served at
`https://coincync.network/legal/`. It is the **website-side**
compliance bundle: privacy policy, terms of use, jurisdiction
statement, and abuse contact. The **protocol-side** compliance bundle
already exists at:

- [docs/DISCLAIMER.md](../DISCLAIMER.md) — protocol disclaimer (no warranty, prohibited uses, no professional services)
- [SECURITY.md](../../SECURITY.md) — responsible disclosure policy
- [CODE_OF_CONDUCT.md](../../CODE_OF_CONDUCT.md) — contributor behavior
- [docs/THREAT_MODEL.md](../THREAT_MODEL.md) — adversary model

This file fills the gap that anti-scam classifiers look for: a clear
statement of who operates the website, what data the website collects
about visitors, and how to contact someone about it. **The protocol
collects nothing about anyone** — these terms govern the website
property only.

---

> **⚠ LAWYER-REVIEW REQUIRED BEFORE PUBLISHING.**
>
> This document is a starting-point template, not legal advice. Have
> a lawyer (ideally one familiar with both crypto and the
> jurisdiction selected in §3) review the entire document before
> publishing on `coincync.network`. The placeholders marked
> `[FILL IN]` are decisions that *only the maintainer* can make.

---

## 1. Privacy policy (website only)

**Effective date:** `[FILL IN once published]`

The CoinCync website (`coincync.network`, `coincync.org`, and any
subdomain operated by the project) is a static information site. It
does not require accounts, does not collect personal information
from visitors, and does not transmit visitor data to third-party
trackers.

### 1.1 What the website collects

- **Standard web-server logs** (IP address, user-agent, referring URL,
  requested path, response code, timestamp). Retained for **30 days**
  for security and operational diagnostics, then deleted. Logs are
  not joined with any other dataset and are not shared with third
  parties except as required by valid legal process directed at
  the website operator (see §3 for who that is).

- **Cloudflare proxy logs.** The site is fronted by Cloudflare for
  DDoS protection. Cloudflare retains its own request logs subject
  to [Cloudflare's privacy policy](https://www.cloudflare.com/privacypolicy/).
  We do not enable Cloudflare Analytics, Cloudflare Zaraz, or any
  Cloudflare cookie-based feature.

### 1.2 What the website does NOT collect

- No cookies (other than transient Cloudflare anti-bot challenges).
- No analytics (no Google Analytics, no Plausible, no Fathom, no
  Matomo, no self-hosted tracker).
- No fingerprinting.
- No email addresses (we do not run a newsletter or signup form).
- No wallet addresses (visitors are not asked to connect a wallet).
- No KYC information.

### 1.3 RPC and explorer endpoints

The public RPC endpoint at `api.coincync.network` and the public
explorer at `explorer.coincync.network` serve **blockchain data
which is public by definition**. They do not require accounts.
Standard web-server logs (per §1.1) apply.

The blockchain itself does not contain personal information about
users — addresses are not linked to real identity by the protocol,
and transaction amounts and recipients are cryptographically
hidden. See [CoinCync's privacy disclaimer](../DISCLAIMER.md) §2.2
for the limitations of that protection.

### 1.4 Your rights

If you wish to request deletion of your IP address from our
30-day rolling log retention, email `[FILL IN — see §4]` with your
approximate visit time and the IP you were assigned. We will
process the request within 30 days. (Note: we do not maintain
durable indices on visitor IP, so this is best-effort against
the rolling window.)

If you are an EU/UK/EEA resident invoking GDPR/UK-GDPR rights, or
a California resident invoking CCPA/CPRA rights, the same email
address is the controller contact.

---

## 2. Terms of use (website only)

**Effective date:** `[FILL IN once published]`

By using `coincync.network` (or any mirror domain operated by the
project), you agree to these terms. If you do not agree, do not
use the website.

### 2.1 No warranty

The website is provided "as is" without warranty of any kind,
express or implied. The information on the website may contain
errors, may become outdated, and is not investment advice, legal
advice, tax advice, or financial advice. See
[docs/DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer of
the underlying protocol.

### 2.2 No accounts, no payments

The website does not host user accounts, does not process
payments, does not custody any funds, and does not sell any
product or service. No transaction conducted with anyone via the
website can ever bind the website operator.

### 2.3 Prohibited uses

You may not use the website to:

- Attempt to gain unauthorized access to underlying systems
  (testing in good faith under [SECURITY.md](../../SECURITY.md) is
  explicitly permitted — that's a different thing).
- Send unsolicited bulk requests intended to disrupt service.
- Misrepresent the website as belonging to a different entity.

### 2.4 Third-party links

The website may link to third-party resources (block explorers,
crypto news outlets, code repositories, academic papers). The
website operator is not responsible for the content, accuracy,
privacy practices, or availability of those resources.

### 2.5 Modifications

These terms may be updated. Material changes will be announced via
the project's official channels at least 30 days before they take
effect, except where a shorter window is required by law.

### 2.6 Severability

If any provision of these terms is held unenforceable, the
remainder remains in effect.

---

## 3. Jurisdiction & legal entity statement

**This is the single most important field for anti-scam
classification. Fill it explicitly.**

> The CoinCync **protocol** is a decentralized open-source software
> project with no operating company, no foundation, and no legal
> entity. See [docs/DISCLAIMER.md](../DISCLAIMER.md) §1.

> The CoinCync **website** (`coincync.network`, `coincync.org`) is
> operated by `[FILL IN: individual maintainer name OR a specific
> legal entity name]` (the "website operator"), located in
> `[FILL IN: country / state]`.

> Any dispute arising out of or relating to the website is governed
> by the law of `[FILL IN: chosen jurisdiction — usually the
> operator's residence]`. The website operator does not consent to
> jurisdiction outside that location for website-related disputes.

> The website is not directed at residents of jurisdictions where
> the operation of privacy-preserving cryptocurrency software is
> prohibited. Visitors are responsible for ensuring their use of
> the website complies with the laws applicable to them.

> The website operator does not knowingly transact with persons or
> entities on the U.S. Treasury OFAC Specially Designated Nationals
> list or analogous sanctions lists in other jurisdictions. If you
> are subject to such sanctions, you may not use the website.

### 3.1 Jurisdiction-decision notes (delete before publishing)

Common choices for solo-operated crypto projects:

- **Individual / no entity, operator's home country.** Simplest. Works
  if the operator is willing to be named or to use a stable
  pseudonym tied to a verifiable identity (e.g., GPG-signed
  statements). Tax implications: income tax applies if any.
- **LLC in operator's home state / country.** Adds liability shield
  for the website only (the protocol is decentralized regardless).
  US LLC formation: $50–$500 + annual fees.
- **Foundation (e.g., Swiss Verein, Cayman foundation).** Useful if
  the operator wants the project visibly separated from any
  individual, and / or wants to accept donations / grants. Setup
  cost: $5k–$50k. Annual maintenance: similar. Usually overkill
  pre-mainnet.

**Recommended for CoinCync at the v1.0 stage:** named individual
maintainer in operator's home country. Lowest cost, lowest scam
signal *if* the operator is named. Pseudonym + foundation is the
fallback if the operator chooses to stay pseudonymous — but expect
classifiers to weight this as a moderate scam signal until a track
record accumulates.

---

## 4. Contact & abuse

| Topic | Email |
|---|---|
| Security vulnerabilities | `CyncLabs@proton.me` (see [SECURITY.md](../../SECURITY.md)) |
| Legal / abuse / takedown | `[FILL IN — recommend abuse@coincync.network]` |
| General questions / press | `[FILL IN — recommend contact@coincync.network]` |
| GDPR / CCPA data requests | (same as legal / abuse above) |

For sanctions-related concerns (suspected use of the website by a
sanctioned person), use the abuse address with subject line
`[SANCTIONS]`.

---

**Publication checklist** (delete before publishing)

- [ ] All `[FILL IN]` placeholders resolved
- [ ] Lawyer review complete
- [ ] Operator name / entity finalized
- [ ] Jurisdiction finalized
- [ ] All three contact emails actually created and routed (test by sending mail to each)
- [ ] Effective dates filled in
- [ ] Section 3.1 (jurisdiction notes) deleted
- [ ] This checklist deleted

---

**Last updated:** 2026-05-26 (draft, not yet published)
