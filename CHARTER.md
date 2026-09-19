# CoinCync — Project Charter

> The north star. This document does not change often. It states **why CoinCync
> exists**, the **commitments** every piece of work answers to, and the **honest
> definition of "done"** for each. Dates, features, and release order live in
> [`ROADMAP.md`](ROADMAP.md); this is the spine those hang off. When a decision is
> hard, the answer is whichever option this charter would choose.

## Why this project exists

CoinCync is private digital cash built to **last**, not to pump. The bet is
simple and unfashionable: that a small, honest, correct privacy coin — with no
premine, no dev tax, and privacy that is mandatory rather than optional — is
worth building carefully even if fame and users arrive slowly. We are explicitly
fine with slow. The only thing we are not fine with is being **wrong** in a way
that costs someone their money or their privacy.

Everything below serves one goal: that a person can hold and move value
privately, and **trust** that it works. In this domain trust is the whole
product. It is earned one careful decision at a time and lost in a single bad
one.

## The four commitments

Every change to CoinCync answers to these, in this order. When they conflict,
the higher one wins.

### 1. Correctness & security come first — always

It is money *and* privacy. A bug here is not a lost point; it is a real person
harmed. So correctness outranks features, speed, and deadlines, without
exception.

- **Definition of done:** the change is covered by tests that fail if the
  behavior regresses; consensus-critical code is hash-locked and changed only
  through a CIP; the security-critical core stays small and auditable; and
  nothing reaches mainnet without a real third-party **audit**.
- **How we hold the line:** `critical_files.lock`, mutation testing, adversarial
  test coverage, the connector/guard architecture that keeps the audited core
  small while features plug in around it, and the standing rule — **testnet-only
  until audit.**

### 2. A real, decentralized network — not a demo

A privacy coin that runs on one box is a screenshot, not a network. Credibility
requires independent nodes, steady blocks, and anyone able to join and run one.

- **Definition of done:** a public testnet of multiple independent nodes that
  produces steady blocks, survives nodes coming and going, has been observed
  running for a sustained period, and that a newcomer can join by following the
  docs — before we ever discuss mainnet.
- **How we hold the line:** the fleet is real infrastructure, joinability is
  tested (the community-bootstrap checks), and the [Crucible](docs/crucible/)
  community-testing program stresses it with real operators.

### 3. Honest privacy — never oversold

The most dangerous thing a privacy tool can do is promise more than it delivers.
We describe exactly what each layer protects and what it does not.

- **Definition of done:** every privacy claim maps to a specific mechanism
  (ring signatures hide the sender, stealth addresses hide the receiver, RingCT
  + Bulletproofs+ hide amounts, Dandelion++ hides the origin IP, Spark for the
  shielded pool), the residual leaks are documented, and no user-facing copy
  uses words like "absolute" or "untraceable" that we cannot defend.
- **How we hold the line:** the [Constitution](CONSTITUTION.md) and
  [Bill of Rights](docs/BILL_OF_RIGHTS.md) make privacy mandatory and
  non-optional; documentation states guarantees *and* limits.

### 4. A disciplined, unhurried path to mainnet

Mainnet is a one-way door. We walk through it only when the first three
commitments are genuinely met — not on a calendar.

- **Definition of done:** every item in
  [`docs/architecture/MAINNET_LAUNCH_CHECKLIST.md`](docs/architecture/MAINNET_LAUNCH_CHECKLIST.md)
  is satisfied, the audit is complete and its findings resolved, the emission
  and fair-launch parameters are frozen and proven, and the testnet has earned
  our confidence. If the date and the readiness disagree, **readiness wins.**
- **How we hold the line:** consensus changes are batched, never sneaked in;
  every consensus change is a CIP; the launch checklist is treated as sacred.

## What CoinCync will not do

Stating the anti-goals is half of a charter. CoinCync will not:

- **Premine or take a dev tax.** Fair launch, 0% dev tax, no founder allocation.
- **Make privacy optional.** It is the only mode the network knows.
- **Overclaim.** No "absolute anonymity," no marketing that outruns the math.
- **Rush consensus.** No consensus change without a CIP, tests, and (for mainnet)
  simulation. No hacking the difficulty or validity rules on a live chain to
  make a demo look good.
- **Optimize for hype.** No artificial scarcity theater, no paid pumping, no
  shortcuts that trade long-term trust for short-term attention.
- **Distribute what we have not verified.** We read, test, and understand before
  we ship or publish.

## How this guides day-to-day work

- Before a change, ask which commitment it serves and whether it clears that
  commitment's definition of done. If it doesn't, it isn't finished.
- Prefer the option that keeps the audited core small and the guarantees honest,
  even when it is more work.
- When something is not yet true, **say so plainly** — in code comments, docs,
  and to each other. Honest "not done yet" beats a confident wrong claim.

## Where we are right now (2026-09)

A snapshot, kept short on purpose — the living detail is in [`ROADMAP.md`](ROADMAP.md).

- **Testnet is live** on the v3 network: a fresh chain on the current
  anchor-binding code, publicly joinable (old pre-reset nodes are rejected at the
  handshake), self-mining, difficulty calibrated. It runs today on a single seed.
- **The current milestone is Commitment #2** — turning that single seed into a
  real multi-node network with steady blocks that outsiders can join. This is the
  next thing we build, and the dress rehearsal for everything after it.
- **Then:** sustained observation → audit → the mainnet checklist → GA. In that
  order. No skipping.

---

*Related: [Constitution](CONSTITUTION.md) · [Bill of Rights](docs/BILL_OF_RIGHTS.md)
· [Roadmap](ROADMAP.md) · [Mainnet Launch Checklist](docs/architecture/MAINNET_LAUNCH_CHECKLIST.md)
· [The Crucible](docs/crucible/) · [Audit submission](docs/audit-submission.md)*

*This charter is a living document. It changes rarely, and only by PR with the
rationale in the commit message — the same discipline we hold everything else to.*
