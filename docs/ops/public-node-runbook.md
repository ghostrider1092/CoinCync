# Public-node runbook — standing up a reachable mesh

**Problem this solves.** A CoinCync node behind NAT (home router, no port-forward)
dials out and syncs perfectly, but **never accepts an inbound connection**. The
network only gossips peers it can connect *back* to, so an un-reachable node is
never advertised: everyone orbits the one seed, no one meshes, and the rig
`≥3-peer` mining gate can never clear. Symptom: on every node,
`get_peers` shows only the seed, and `get_info` reports `inbound_reachable: false`
(and the node logs a one-shot "NOT inbound-reachable" warning after ~10 min).

The fix is **topology, not code**: you need ≥2–3 nodes that are
**inbound-reachable** and cross-connected.

The node's P2P port is the network port (testnet default **28080**). The RPC
(28081), metrics (28082) and REST (28083) stay bound to `127.0.0.1` and must
**not** be exposed.

---

## A. Recommended: public VPS nodes (reachable by default)

A VPS has a public IP, so it accepts inbound with no NAT games. Two or three
small instances ($4–5/mo each, e.g. Hetzner CX11) form a solid backbone.

On each VPS (`vps1`, `vps2`, `vps3`), run the node pointed at the seed **and at
each other** — the cross-connect is what makes them mesh:

```bash
coincync-node --network testnet --data-dir ~/.coincync \
  --addnode 2.29.34.197:28080 \
  --addnode <vps2-ip>:28080 \
  --addnode <vps3-ip>:28080
```

Open the P2P port in the host firewall (inbound TCP 28080):

```bash
# ufw
sudo ufw allow 28080/tcp
# firewalld
sudo firewall-cmd --permanent --add-port=28080/tcp && sudo firewall-cmd --reload
# nftables / cloud security group: allow inbound TCP 28080 from 0.0.0.0/0
```

Leave RPC/metrics/REST closed (they listen on localhost only; do not forward
them, and do not bind them to 0.0.0.0).

---

## B. Home / NAT nodes (rigs behind a router)

A home machine can be a reachable node too, but you must forward the port:

1. Give the machine a static LAN IP (DHCP reservation).
2. On the router, **forward inbound TCP 28080 → that machine's LAN IP:28080**.
   UPnP is attempted automatically but is unreliable/often disabled — do the
   manual forward.
3. Run the node, cross-connected like the VPS nodes:
   ```
   coincync-node --network testnet --data-dir ~/.coincync \
     --addnode 2.29.34.197:28080 --addnode <vps1-ip>:28080
   ```
4. CGNAT caveat: some ISPs put you behind carrier-grade NAT, where no
   port-forward works. Those machines can only ever be outbound-only — use a VPS
   for a reachable node instead.

---

## C. DNS seeds (so bootstrap finds more than one node)

Right now `seed{1,2,3}.coincync.network` all resolve to the single seed, so a
fresh node only bootstraps to one peer. Point each seed record at a *different*
reachable node's public IP (A/AAAA records). Then a new node discovers the whole
backbone on first boot without any `--addnode`.

---

## D. Verify reachability

On each node, after it has been up a few minutes:

```bash
curl -s -X POST http://127.0.0.1:28081 -H 'content-type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"get_info","params":[]}' \
  | jq '{height, peer_count, inbound_peers, inbound_reachable}'
```

- `inbound_reachable: true` and `inbound_peers > 0` → the node is reachable and
  being meshed; its address will be gossiped.
- `inbound_reachable: false` after ~10 min (and the log warning) → still
  outbound-only; the port-forward / firewall isn't working. Re-check B/A.

Cross-check from another machine that the port is actually open:

```bash
nc -vz <node-public-ip> 28080      # or: nmap -p 28080 <node-public-ip>
```

---

## E. Checklist

- [ ] ≥2–3 nodes with public IPs (or working port-forwards)
- [ ] Inbound TCP 28080 open on each
- [ ] Each node `--addnode`s the *others*, not just the seed
- [ ] RPC/metrics/REST left on `127.0.0.1` (never exposed)
- [ ] DNS seeds point at the different node IPs
- [ ] `get_info.inbound_reachable == true` on each
- [ ] A rig now sees ≥3 peers → its mesh gate clears → it mines

Once this holds, the network is a real mesh instead of a hub-and-spoke around one
seed, and new operators who follow the same steps join it automatically.
