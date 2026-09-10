# Mainnet launch checklist

Operator runbook for the CoinCync mainnet genesis (target **2026-10-01
00:00:00 UTC**). This file is referenced from `src/network/dns_seeds.rs`
(mainnet seed placeholders) and consolidates the go/no-go items that cannot
be satisfied by code alone.

Status legend: `[ ]` outstanding · `[x]` done · `[~]` in progress.

> The **final testnet** (tag `v2.0.0-testnet`) is the dress rehearsal for
> everything below: the same 2.0.0 code, built with testnet consensus
> params. Nothing here should first be exercised on mainnet.

---

## 1. Seed / bootstrap infrastructure  — BLOCKING

- [ ] **Provision ≥3 mainnet seed nodes** on independent hosts/ASNs. The
  ≥3-redundancy floor exists so a single host outage cannot strand
  bootstrap. (Testnet currently runs a single fallback IP — do **not**
  carry that pattern into mainnet.)
- [ ] **Replace the mainnet seed placeholders** in `src/network/dns_seeds.rs`
  (`MAINNET_FALLBACK`). As of this writing they hold a **testnet-fleet IP
  used as a placeholder** (`2.28.1.75:19080`), not real mainnet seeds.
- [ ] **Register DNS seeds** `seed1/2/3.coincync.org` (A + AAAA) pointing at
  the provisioned seed boxes, and confirm they resolve from multiple
  resolvers before launch. Bootstrap must not depend on the hardcoded
  fallback alone.
- [ ] Confirm mainnet P2P/RPC ports (`19080` / `19081`) are open on the seed
  hosts and firewalled appropriately (RPC not world-exposed).

## 2. Genesis  — BLOCKING

- [x] Mainnet genesis timestamp `1790812800` (2026-10-01 UTC) and message
  set (`src/mainnet.rs`).
- [x] Mainnet genesis hash `c9eb73ab…635c` set and guarded by a consistency
  test.
- [x] No premine / no dev-tax: genesis coinbase pays an unspendable all-zero
  key; `DEV_TAX_PERCENT = 0` with a compile-time constitutional assert.
- [ ] Run/record the genesis ceremony per `docs/launch/GENESIS-CEREMONY-PLAN.md`
  and reconcile against `GENESIS-DECISIONS-WORKSHEET.md`.

## 3. Consensus finalization  — BLOCKING (needs crypto review)

Per `ROADMAP.md`, the following are open decisions that the mainnet RC
(v1.0.16 line / 2.0.0) is meant to freeze. They must be closed **before**
tagging a mainnet binary:

- [ ] **ASERT difficulty halflife** — confirm the final value.
- [ ] **MESS (reorg-defense) variant** — accept/reject and wire if accepted.
- [ ] **Populate `CONSENSUS_CHECKPOINTS`** (mainnet table) and the
  `activation_height()` registry — both are intentionally empty pre-launch;
  every Mode-A fork depends on the registry being populated.

## 4. Version / release  — BLOCKING

- [x] Workspace version is `2.0.0` (the mainnet milestone; commit `13a50c7`).
- [ ] Cut the mainnet tag `v2.0.0` (no `-testnet` suffix) so `release.yml`
  builds **mainnet** binaries (`--features "randomx"`, testnet switch OFF)
  across Linux (reproducible Docker path), Windows, and macOS.
- [ ] Verify the published `SHA256SUMS` and Sigstore build-provenance
  attestations, and that a community `bash scripts/build-in-docker.sh`
  (no `--testnet`) reproduces the Linux binaries byte-for-byte.

## 5. Documentation / comms

- [ ] Refresh `CHANGELOG.md` through the 2.0.0 release.
- [ ] Publish the mainnet announcement and seed/DNS details to the community.

---

*This checklist is intentionally conservative: any BLOCKING item still open
is a no-go for the 2026-10-01 genesis. Keep it in sync with `ROADMAP.md` and
`src/network/dns_seeds.rs`.*
