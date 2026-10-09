# CoinCync

A privacy cryptocurrency with CPU-only proof of work.

## What it is

CoinCync is a privacy-by-default blockchain. Every transaction hides its sender, its recipient, and its amount, using:

- **CLSAG ring signatures** — the sender is one of N possible signers, and which one is computationally indistinguishable
- **Stealth addresses** — every transaction output is a one-time address that only the recipient can recognize
- **Bulletproofs+ range proofs** — amounts are encrypted, but the network can prove they fall in a valid range without learning the value
- **MimbleWimble cut-through** (Phase 2, designed) — historical transaction graphs collapse, leaving only unspent commitments
- **Lelantus Spark shielded pool** (Phase 2, **built & soak‑tested, gated OFF pre‑audit**) — replaces the fixed decoy ring with a pool‑sized anonymity set (production target Firo‑class, 32,768) and a logarithmic‑size spend proof, via the vendored libspark engine

> Activation status: the shielded (Lelantus‑Spark) pool is fully implemented and
> has passed a 24‑hour in‑block consensus soak, but its activation height is
> `u64::MAX` on **testnet and mainnet** — permanently disabled until an external
> security audit. It can only be switched on in a feature‑gated build on the
> isolated **regtest** and **beta** networks. A normal binary is byte‑identical
> with shielded off on every network.

Mining is **RandomX only** by [Constitution Article V](./governance/constitution.md#article-v--open-mining) — the same CPU-biased, memory-hard PoW algorithm Monero has used in production since 2019. Any laptop can participate. No ASICs, no GPU farms, no permission, no KYC, no stake. See [Consensus & PoW](./protocol/consensus.md) for the full rationale on why a single strong algorithm is stronger than a rotation.

## What it isn't

- **Not transparent.** Unlike Zcash, there is no transparent escape hatch. Every transaction goes through the privacy machinery — there is no `t-addr` to launder funds out of. Mandatory privacy is enforced as a consensus rule, not as a recommendation.
- **Not premined.** Every coin is mined by someone. There is no founder allocation, no ICO, no airdrop, no dev tax.
- **Not behind a CDN.** The public infrastructure (block explorer, RPC API, landing page) is run as a federation of independent Caddy hosts under the operator's direct control. No traffic passes through a third-party MITM. See [Federation & DDoS](./operations/federation-and-ddos.md) for the full reasoning.
- **Not opaque to its users.** [View keys](./protocol/privacy-model.md#view-keys) let any wallet holder selectively disclose to an exchange, an auditor, or a tax authority — without breaking privacy for anyone else.

## What's in these docs

| Section | What you'll find |
|---|---|
| [Getting started](./getting-started/build.md) | Build the binary, run a testnet node, create a wallet |
| [Protocol](./protocol/privacy-model.md) | The cryptographic guarantees, the consensus model, the emission curve, the transaction wire format |
| [API reference](./api/json-rpc.md) | JSON-RPC 2.0 and REST endpoint inventory with examples |
| [Operations](./operations/deployment.md) | Running production nodes, deploying the explorer, federation, Tor hidden services |
| [Governance](./governance/constitution.md) | The constitution, the bill of rights, what changes can and can't be made, the disclaimer |

## Where the live data is

- **Block explorer** — [explorer.coincync.network](https://explorer.coincync.network)
- **Public RPC API** — [api.coincync.network](https://api.coincync.network)
- **Source code** — [git.coincync.network/coincync/cync-protocol](https://git.coincync.network/coincync/cync-protocol)
- **Network status (testnet)** — see the explorer

## Status

CoinCync is **pre-launch on mainnet**. The current testnet is live and stable. Mainnet genesis is scheduled for **March 1, 2027 00:00:00 UTC**. Until then, the explorer and API surfaces serve testnet data; mainnet selectors return a launch countdown.

For protocol decisions, design notes, and the why-it-works-this-way reasoning, start with [Privacy model](./protocol/privacy-model.md) and read forward.
