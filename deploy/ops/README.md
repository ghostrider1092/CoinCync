# Testnet operations

Scripts and templates for **community joinability**: DNS bootstrap, inbound P2P, and release installs.

## Verify bootstrap health

| Script | Environment |
| --- | --- |
| [`verify-community-bootstrap.sh`](./verify-community-bootstrap.sh) | Linux/macOS/Git Bash — DNS (`dig`) + TCP probes |
| [`../../scripts/verify-community-join-readiness.ps1`](../../scripts/verify-community-join-readiness.ps1) | Windows PowerShell |

Default behavior: **all DNS seeds must resolve**, and **at least one** hardcoded seed must accept TCP on port **28080** (same idea as home users behind picky ISPs).

Strict TCP (every seed must answer):  
`COINCYNC_STRICT_TCP=1 bash verify-community-bootstrap.sh`  
PowerShell: `-StrictTcp`

## Install a seed/relay node (systemd)

1. Build or download a **testnet** `coincync-node` ([release workflow](../../.github/workflows/release.yml) produces artifacts).
2. Copy the binary to `/usr/local/bin/coincync-node` and `chmod +x`.
3. **Cloud firewall** (e.g. DigitalOcean): allow **inbound TCP 28080** to this droplet.
4. On the server:

```bash
sudo cp coincync-node /usr/local/bin/coincync-node
sudo chmod +x /usr/local/bin/coincync-node
cd /path/to/coincync/repo
sudo bash deploy/ops/install-testnet-node.sh --open-ufw
```

`--open-ufw` adds a host `ufw` rule if `ufw` is installed; you still need the **cloud** rule.

Unit file source: [`../coincync-node.service`](../coincync-node.service) — testnet P2P **28080**, RPC bound to **127.0.0.1:28081**.

## Related docs

- [Run a node](../../docs/src/getting-started/run-a-node.md) — CLI flags and RPC curls
- [Release README](../../release/README.md) — tarball contents and checksums
