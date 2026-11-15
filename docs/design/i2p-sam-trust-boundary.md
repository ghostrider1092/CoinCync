# I2P transport: the external-SAM trust boundary

CoinCync reaches I2P through an **external SAM v3 bridge** — a separately-run
`i2pd` or Java-I2P router with its SAM API enabled (default `127.0.0.1:7656`).
CoinCync is a **SAM client**, not an embedded I2P router. This document states
what lives on each side of that boundary, because two of the I2P threats
(NetDb segmentation and reseed decentralization) are the **router's**
responsibility, not the blockchain client's, and that is a deliberate design
choice — not a gap.

## Who owns what

**The external SAM bridge (the operator's i2pd / Java-I2P router) owns:**

- The I2P router and its **Network Database (NetDb)**, floodfill interaction,
  and exploratory vs. client tunnels.
- **Tunnel building and rotation** (~10 min), LeaseSet publication, and the
  destination's reachability on the overlay.
- The **NTCP2 / SSU2** transports and their clock-sensitive handshakes.
- **Reseed**: bootstrapping into the I2P overlay from signed (`SU3`) reseed
  servers.

**CoinCync (the SAM client) owns** (all on `feat/net-addrv2`):

- The SAM session lifecycle: `SESSION CREATE` (Ed25519 / `SIGNATURE_TYPE=7`),
  a **persistent destination key** on disk (`<data_dir>/i2p_dest.key`) for a
  stable `.b32.i2p` across restarts, a generous cold-start timeout, and a
  control-socket **supervisor**.
- Outbound `STREAM CONNECT` dialing and an inbound **`STREAM ACCEPT` pool** (so
  the node is dialable over I2P).
- The **blockchain** peer store (addrv2): per-source caps, new/tried buckets,
  aging, persistence — anti-eclipse for *blockchain* peers, distinct from the
  router's NetDb.
- Origin obfuscation (**Dandelion++**), frame **size padding** and cover
  traffic, the scorer **exemption** for the shared SAM/proxy address, the
  **clearnet-leak guards** and **addrv2 IP-scrub** under onion-only, and the
  **clock-skew** diagnostic.

## Threat #2 — NetDb segmentation / destination ↔ router linking

*Risk:* if a blockchain node **embeds** an I2P router and answers a client
LeaseSet on its main/exploratory NetDb, an attacker who queries that router can
link the `.b32.i2p` destination to the operator's clearnet IP.

*How the external-bridge design addresses it:* CoinCync embeds **no** router,
so there is no CoinCync-owned NetDb for an attacker to query, and no path by
which the blockchain process answers NetDb lookups. The client LeaseSet is
created and published by the external router, which (in both `i2pd` and Java
I2P) publishes a client destination's LeaseSet down **client tunnels only**,
never via the router's exploratory/main NetDb. If we ever ship an embedded
router, this becomes our problem and we must enforce sub-DB / client-NetDb
segmentation then.

*Operator guidance:* run a dedicated or properly-segmented `i2pd`; do not expose
the router console or its NetDb publicly; keep the SAM API bound to localhost.

## Threat #4 — reseed centralization / cold-start poisoning

*Risk:* a single hardcoded, unsigned reseed server is a single point of failure
and a censorship/poisoning chokepoint for joining the I2P overlay.

*How the external-bridge design addresses it:* joining the **I2P overlay** is
the router's job — `i2pd` and Java I2P ship multiple geographically distributed,
`SU3`-signed reseed endpoints by default. CoinCync never bootstraps the I2P
overlay itself. What CoinCync bootstraps is its **blockchain** peer set, via its
own peer exchange — addrv2 gossip, `--addnode <host>.onion` / `<host>.b32.i2p`
seeds, and periodic relay — which is independent of I2P reseed and is hardened
separately (per-source caps, new/tried buckets).

*Operator guidance:* configure multiple reseed URLs in the router if the
defaults are blocked in your region.

## Related host concerns

- **Clock skew** (NTCP2/SSU2 reject > ~60 s drift): enforced by the router, but
  CoinCync adds a peer-sampled **clock-skew diagnostic** (`net_time`) that warns
  the operator at startup, since a skewed host clock silently breaks the
  router's tunnel building.
- **File descriptors:** each peer costs an fd (plus the SAM stream for anon
  peers); CoinCync warns at startup if `ulimit -n` is low, and caps concurrent
  anon streams (`MAX_I2P_INBOUND` inbound + `ONION_OUTBOUND_BUDGET` outbound).

## Operator checklist

1. Run `i2pd` (or Java I2P) with SAM enabled on `127.0.0.1:7656`; start CoinCync
   with `--i2p-sam 127.0.0.1:7656`.
2. Keep the router's clock **NTP-synced**.
3. Keep the router console / NetDb **non-public**; SAM bound to localhost.
4. Configure **multiple reseed URLs** if the defaults are censored.
5. The persistent destination key (`i2p_dest.key`) is CoinCync's, stored in the
   node's data-dir — back it up to keep a stable `.b32.i2p`.
