# Run a community-operated CoinCync testnet seed node

The CoinCync testnet currently runs on 5 Vultr boxes operated by
the project maintainer. That's enough for the chain to function,
but it's a single point of trust — one operator running every
node means one operator can theoretically censor, delay, or
manipulate the network.

**Community-operated seed nodes fix that.** Even one box run by
a different person, on a different provider, in a different
country, materially changes the trust model. Listing services
(CoinGecko, CMC), audit firms, and exchanges all check "is this
chain decentralized?" — independent operators are how you prove
yes.

This guide is for someone who wants to help the network for its
own sake, not to mine or extract value. Running a seed node costs
~$5-25/month depending on provider and produces nothing tangible
in return except a name in the CoinCync acknowledgments and the
satisfaction of helping a privacy POW chain be more than one
person's project.

---

## What a seed node does

- Listens on a public IP, accepts inbound P2P connections from
  any peer (miners, wallets, other seeds)
- Relays blocks and transactions across the network
- Helps new nodes find peers when they first start up (DNS
  bootstrap → seed → full peer table)
- Does NOT mine, does NOT serve a wallet, does NOT touch funds

A seed node is the most boring possible piece of crypto
infrastructure. That's the point — it should just sit there
and forward bytes.

---

## What you need

- A VPS with a public IP (no DHCP, no double-NAT). Recommended specs:
  - 4 GB RAM
  - 2 vCPU
  - 80 GB SSD
  - Ubuntu 22.04 LTS or Debian 12
- Open inbound port 28080 (TCP) in the provider's firewall
- ~10 GB of bandwidth per month (CoinCync testnet is low volume)
- Ability to SSH in as root (or a sudo user)

**Cheapest providers** (all work fine):

|Provider|Cheapest plan that works|Cost/mo|
|---|---|---|
|Hetzner|CX22 (2 vCPU, 4 GB)|~$5 (EUR)|
|OVH|VPS Starter (1 vCPU, 2 GB) — borderline; VPS Value (2 vCPU, 4 GB) is safer|~$5-10|
|Vultr|Cloud Compute Regular 4GB|~$24|
|DigitalOcean|Basic Droplet 4GB|~$24|
|Contabo|VPS S|~$5|
|Linode (Akamai)|Nanode → Dedicated 4GB|~$24|

The cheap European options (Hetzner, OVH, Contabo) are fine
technically. Vultr/DO/Linode are pricier but have better global
network paths.

**Where to host** (geographic spread matters): pick a region the
existing 5 seeds DON'T cover. Current coverage: NJ (US), SFO
(US), Frankfurt (DE), Amsterdam (NL), Tokyo (JP), Sydney (AU),
Dallas (US). Underserved continents: South America, Africa, India.
Even a São Paulo or Mumbai node materially expands the network's
geographic reach.

---

## Setup in 5 commands

After SSH-ing into your new VPS:

```bash
# 1. Download the latest testnet binary (Linux x86_64)
#    Native Linux binaries are added by the v1.0.10 release workflow;
#    for v1.0.9-testnet-pre-audit you'll need to build from source:
git clone https://github.com/ghostrider1092/Coincync-Testnet- coincync
cd coincync && cargo build --release --bin coincync-node

# 2. Open port 28080 inbound (Ubuntu/Debian with ufw)
sudo ufw allow 28080/tcp
sudo ufw enable

# 3. Create a systemd service file
sudo tee /etc/systemd/system/coincync-node.service > /dev/null <<'EOF'
[Unit]
Description=CoinCync testnet seed node
After=network-online.target

[Service]
Type=simple
User=root
ExecStart=/root/coincync/target/release/coincync-node \
    --network testnet \
    --p2p-bind 0.0.0.0:28080 \
    --rpc-bind 127.0.0.1:28081 \
    --addnode 66.135.23.193:28080 \
    --addnode 140.82.57.168:28080 \
    --addnode 207.148.111.76:28080 \
    --log-level info
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 4. Start it
sudo systemctl enable --now coincync-node

# 5. Verify it's syncing
sudo journalctl -u coincync-node -f
# Expect to see "Connected to peer ..." lines within 30 sec
# Expect to see "Imported block at height N" lines as it catches up
```

Initial sync from genesis takes 1-2 hours on most boxes. After
that the node stays at tip with negligible CPU.

---

## What to send to the maintainer for inclusion

Once your node is online and syncing, post in the CoinCync
Discord `#dev-updates` channel:

```
- Public IP: <your IP>
- Region: <city/country>
- Provider: <Hetzner/OVH/Vultr/...>
- Your handle (for credit in the announcement): <name or alias>
- Confirmed: port 28080 open, node syncing, peer count >= 3
```

The maintainer will:

1. Confirm the node is reachable + syncing
2. Add it to the official testnet seed list in the next release
3. Credit you in the v1.0.10-testnet-community announcement and on
   the project's "Network operators" page (once that page exists)

---

## What the maintainer commits to in return

- **No code that "phones home" from your node.** The node connects
  only to other CoinCync peers and the DNS seeds you configure.
- **No analytics, no telemetry, no operator tracking** beyond what
  you voluntarily submit (above).
- **Public credit** when you ask for it; anonymous slot if you'd
  prefer that.
- **Heads-up on consensus changes** with at least 7 days notice
  before a hard fork.
- **A way out:** if you want to stop running the node, just stop
  the systemd service. No paperwork, no permission needed.

---

## What the maintainer asks of you

- **Run a recent release.** Don't stick on a binary from 6 months
  ago — that's how the network forks. Watch
  github.com/ghostrider1092/Coincync-Testnet-/releases for new
  versions.
- **Tell us if you're going to stop running it.** Doesn't have to
  be advance notice — even "I shut it down last week" lets us
  remove the IP from the seed list cleanly.
- **Don't run a modified binary as a public seed.** If you want
  to hack on the code, run a separate instance not in the seed
  list. The seed slot is for the canonical release binary so
  bootstrapping peers get consistent behavior.

---

## What you should NOT do

- **Don't expose port 28081 (RPC) publicly.** That's the
  authenticated control plane for the node. Leave it on
  `127.0.0.1` per the systemd unit above. The project's public
  RPC at `api.coincync.network` is its own hardened setup with
  bearer-token auth — your seed node is just for P2P.
- **Don't run a wallet with funds on the same box.** Seed nodes
  are public-facing and a higher-value target than a private
  miner. Keep your wallet elsewhere.
- **Don't share the systemd unit file with your AWS/Vultr API
  key embedded.** This guide deliberately uses systemd unit files
  with no secrets — keep it that way.

---

## Mainnet (October 1, 2026)

This guide is for **testnet** seed nodes. Mainnet seed nodes are a
separate set with stricter operational requirements — see
[GENESIS-CEREMONY-PLAN.md §1](../../launch/GENESIS-CEREMONY-PLAN.md)
when that work begins. Running a testnet seed node is good practice
and prerequisite-but-not-promise for running a mainnet seed when
the time comes.

---

**Last updated:** 2026-05-27
**Questions:** post in CoinCync Discord `#dev-updates` or email
`CyncLabs@proton.me`.
