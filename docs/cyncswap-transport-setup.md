# `cyncswap` Coordinator Transport Setup

Operator guide for running the CIP-001 atomic-swap coordinator over
the three supported transports: **plain TCP**, **Noise XX over TCP**,
and **Noise XX over Tor (via SOCKS5)**. Pick one based on your threat
model:

| Transport | Confidentiality | Mutual auth | Hides Bob's IP | Use case |
| --- | --- | --- | --- | --- |
| Plain TCP | ❌ | ❌ | ❌ | Localhost dev, trusted LAN, smoke tests |
| Noise XX over TCP | ✅ (ChaCha20-Poly1305) | ✅ (Curve25519 long-term keys) | ❌ | Internet, with both parties' IPs known + acceptable |
| Noise XX over Tor (SOCKS5) | ✅✅ (Noise + Tor circuit) | ✅ (Noise mutual-auth) | ✅ (via Tor) | Production / privacy-preserving |

The transport choice does not affect the swap protocol; the same
`run_alice` / `run_bob` driver runs over any of them. **For production
swaps, use Noise XX over Tor.**

---

## 0. Post-install verification

Before configuring any transport, confirm the binary is functional:

```bash
cyncswap selftest
```

Exercises every cryptographic primitive (cross-curve DLEQ, BTC + CYNC
adaptors, key-derivation joint-key/joint-secret round-trip, Noise
static-pubkey derivation) and reports PASS/FAIL + elapsed time per
check. Default run is sub-millisecond per check; with
`--features strict-dleq` enabled (operator-built binary) the strict-DLEQ
prove+verify cycle adds ~300-500 ms.

Exit code 0 on all-green, 1 on any failure. Run this in CI / install
scripts to catch broken builds before they reach the wire.

---

## 1. Plain TCP

Simplest setup. No encryption beyond what the underlying network
provides. Suitable only for loopback or fully trusted networks.

**Alice (responder):**

```rust
use coincync_swap::coordinator::{Coordinator, Pubkeys, AdaptorBundle};

let mut coord = Coordinator::listen("0.0.0.0:9000", swap_id)?;
coord.run_alice(alice_pubkeys, swap_params, alice_adaptors, verifier)?;
```

**Bob (initiator):**

```rust
let mut coord = Coordinator::connect("alice.example.com:9000", swap_id)?;
coord.run_bob(bob_pubkeys, bob_adaptors, verifier)?;
```

**Caveat.** Anyone on the path can read every byte of the handshake,
modify it, or impersonate either party. Do not use against the open
internet.

---

## 2. Noise XX over TCP

Mutual-auth + confidentiality + integrity via the `Noise_XX_25519_
ChaChaPoly_BLAKE2s` pattern. Each party has a 32-byte Curve25519
long-term static key; both sides learn the other's key during the
3-message XX handshake. **Out-of-band fingerprint verification is
required to defend against MitM**.

### 2.1 Generate the long-term static key

The key is just 32 random bytes. Do this once per party — the same
key can be reused across many swaps. The `cyncswap` CLI ships a
purpose-built subcommand that generates the private + prints the
public fingerprint in one step:

```bash
cyncswap noise-keygen --out ~/.coincync/swap-noise-static.bin
chmod 0400 ~/.coincync/swap-noise-static.bin
# stderr printed: wrote 32-byte Noise static private to ...
# stderr printed: public-key fingerprint (share out-of-band): <64 hex chars>
# stdout printed: <same 64 hex chars>   (suitable for piping)
```

To re-derive the fingerprint later (e.g., to confirm a stored private
still produces the published public):

```bash
cyncswap noise-pubkey --secret-file ~/.coincync/swap-noise-static.bin
# prints: <64 hex chars>
```

Or via hex if you've stashed the secret outside a file:

```bash
cyncswap noise-pubkey --secret-hex <64-hex-chars>
```

The derivation follows RFC 7748 X25519 clamping — matches `snow`'s
internal derivation byte-for-byte, so the output is exactly what the
peer's `NoiseTransport::remote_static()` will report after a
successful XX handshake.

**Manual fallback** (without `cyncswap` on PATH):

```bash
# Linux / macOS / WSL
head -c 32 /dev/urandom > ~/.coincync/swap-noise-static.bin
chmod 0400 ~/.coincync/swap-noise-static.bin

# Or via openssl
openssl rand -out ~/.coincync/swap-noise-static.bin 32

# Or via PowerShell on Windows
$bytes = New-Object byte[] 32
[Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
[IO.File]::WriteAllBytes("$env:USERPROFILE\.coincync\swap-noise-static.bin", $bytes)
```

In the manual case you'll need a separate step to compute the public
fingerprint — `cyncswap noise-pubkey --secret-file <path>` handles
that.

### 2.2 Run

**Alice (responder):**

```rust
let local_static = std::fs::read("~/.coincync/swap-noise-static.bin")?;
let local_static: [u8; 32] = local_static.as_slice().try_into()?;

let mut coord = Coordinator::listen_noise("0.0.0.0:9000", swap_id, &local_static)?;

// After listen_noise returns, the Noise XX handshake has completed.
// Bob's long-term key is now visible — verify it matches the
// fingerprint Bob shared with us out-of-band.
let bob_fingerprint_expected: [u8; 32] = /* loaded from your address book */;
let bob_fingerprint_actual = coord.remote_static().unwrap();
if bob_fingerprint_actual != bob_fingerprint_expected {
    return Err("MitM detected: Bob's Noise key doesn't match expected fingerprint".into());
}

coord.run_alice(alice_pubkeys, swap_params, alice_adaptors, verifier)?;
```

**Bob (initiator):**

```rust
let local_static = std::fs::read("~/.coincync/swap-noise-static.bin")?;
let local_static: [u8; 32] = local_static.as_slice().try_into()?;

let mut coord = Coordinator::connect_noise("alice.example.com:9000", swap_id, &local_static)?;

let alice_fingerprint_actual = coord.remote_static().unwrap();
if alice_fingerprint_actual != alice_fingerprint_expected {
    return Err("MitM detected".into());
}

coord.run_bob(bob_pubkeys, bob_adaptors, verifier)?;
```

### 2.3 Fingerprint exchange

You can exchange Noise static-key fingerprints over any
already-authenticated channel:

- Signal / Matrix DM with verified safety numbers
- PGP-signed email
- In-person QR code
- Voice call where you spell out the hex (32 bytes = 64 hex chars; use
  the `[u8; 32]` → hex helper or `xxd`)

**Do not** exchange fingerprints over the same untrusted network you
plan to swap over — that defeats the purpose.

---

## 3. Noise XX over Tor (via SOCKS5)

Adds **Bob's IP-hiding** on top of Noise XX. Bob's traffic is
encrypted twice: once by the Noise session, once by Tor's circuit.
Alice exposes her listener as a `.onion` hidden service so Bob never
learns Alice's IP either.

### 3.1 Alice: expose her listener as a hidden service

Install Tor on Alice's machine:

```bash
# Debian / Ubuntu
sudo apt install tor

# macOS (Homebrew)
brew install tor

# Or use Tor Browser's bundled tor binary (path varies)
```

Edit `/etc/tor/torrc` (or `$BREW_PREFIX/etc/tor/torrc` on macOS) to add a
hidden service pointing at Alice's `cyncswap` listener port:

```text
# Alice's cyncswap hidden service.
HiddenServiceDir /var/lib/tor/cyncswap/
HiddenServiceVersion 3
HiddenServicePort 9000 127.0.0.1:9000
```

Restart Tor:

```bash
sudo systemctl restart tor
```

After a few seconds, Tor writes Alice's onion address to
`/var/lib/tor/cyncswap/hostname`. Read it:

```bash
sudo cat /var/lib/tor/cyncswap/hostname
# → abcdef1234567890...onion
```

This is the address Alice shares with Bob alongside the `swap_id`. v3
onions are 62 characters (56 base32 + `.onion` suffix).

Alice runs `cyncswap` exactly the same way as in §2 — `listen_noise`
on `127.0.0.1:9000` (the hidden service forwards to it). Alice does
not need to know that Bob is dialing via Tor.

### 3.2 Bob: dial through Tor

Bob needs a Tor instance providing a SOCKS5 proxy. Tor Browser's
bundled tor listens on `127.0.0.1:9150` by default; the standalone
`tor` daemon listens on `127.0.0.1:9050`.

```rust
let local_static = std::fs::read("~/.coincync/swap-noise-static.bin")?;
let local_static: [u8; 32] = local_static.as_slice().try_into()?;

let mut coord = Coordinator::connect_noise_via_socks5(
    "127.0.0.1:9050",                       // local Tor SOCKS5
    "abcdef1234567890...onion",             // Alice's hidden service (no port suffix)
    9000,                                    // the port from HiddenServicePort
    swap_id,
    &local_static,
)?;

let alice_fingerprint_actual = coord.remote_static().unwrap();
// Verify against the fingerprint Alice published alongside the .onion.
if alice_fingerprint_actual != alice_fingerprint_expected {
    return Err("MitM detected".into());
}

coord.run_bob(bob_pubkeys, bob_adaptors, verifier)?;
```

That's it. Bob's `cyncswap` process knows nothing about Tor beyond the
proxy address; `tor` handles circuit construction and `.onion`
resolution.

### 3.3 Why both Noise AND Tor?

Tor provides:

- IP-hiding for both parties (Bob doesn't learn Alice's IP; Alice
  doesn't learn Bob's IP)
- Circuit-level encryption against passive observers

Tor does NOT provide:

- Mutual authentication of long-term party identities. The `.onion`
  address authenticates Alice's hidden service, but only via the Tor
  hidden-service-directory consensus — not via a key Alice + Bob
  manage themselves.
- End-to-end confidentiality if the hidden service is compromised or
  the operator publishes the wrong `.onion`.

Noise XX provides the additional mutual-auth layer rooted in
operator-managed keys, which is what the swap protocol's adaptor
material is bound to.

**Conclusion: use both layers together for production swaps.**

---

## 4. Quick-reference: which constructor to call

| Scenario | Alice | Bob |
| --- | --- | --- |
| Localhost dev | `listen` | `connect` |
| Trusted LAN | `listen` | `connect` |
| Internet, IPs ok to reveal | `listen_noise` | `connect_noise` |
| **Production / privacy** | `listen_noise` (with torrc HiddenService pointing at the listener port) | `connect_noise_via_socks5` (with local Tor SOCKS5) |
| Internet without Tor + want privacy via VPN only | `listen_noise` | `connect_noise` (Bob runs his cyncswap process inside a VPN-tunneled namespace) |

---

## 5. Operational notes

- **Timeouts.** Default per-operation socket timeout is 30 seconds.
  Tighten via `coord.set_timeout(Duration::from_secs(5))` if your
  operator workflow benefits from faster failure detection.
- **One swap per listen.** Each `listen*` call accepts exactly one
  inbound connection then returns. For multiple concurrent swaps,
  spawn multiple listeners on different ports.
- **`MAX_FRAME_BYTES = 16 MiB`** caps both inbound and outbound
  message size. Comfortably above strict-DLEQ proof worst-case
  (~81 KB).
- **Noise chunking.** Messages larger than ~65 KiB (Noise spec
  message limit minus AEAD tag) are split into multiple AEAD frames
  internally — transparent to the caller; the receiver reassembles.
- **DoS-hardened listener variants** are available via
  `Coordinator::listen_filtered(endpoint, swap_id, peer_timeout,
  max_attempts)` and `listen_noise_filtered(endpoint, swap_id,
  local_static_key, peer_timeout, max_attempts)`. These do
  accept-then-validate-Hello-then-loop: peers that don't send a
  valid Hello matching `swap_id` within `peer_timeout` (or can't
  complete the Noise handshake, for the noise variant) are dropped,
  and the next peer is tried, up to `max_attempts` times. Pair with
  `run_alice_post_hello` rather than `run_alice` (the filtered
  listen already consumed the Hello). Production default:
  `peer_timeout = 5s, max_attempts = 100`. The simple
  `listen` / `listen_noise` variants remain available for testing +
  single-shot use cases.
- **`run_alice` / `run_bob` are sync.** No tokio runtime needed. Spawn
  your own thread if you want to drive multiple swaps in parallel.
- **The plain-TCP and Noise-XX transports share the same wire-level
  length-prefix framing.** A listener on the same port doesn't need
  to advertise which mode it's using; the operator chooses at
  `listen` vs `listen_noise` time, and the connecting peer must use
  the matching constructor.

---

## 6. See also

- [docs/cip/CIP-001-atomic-swap.md](cip/CIP-001-atomic-swap.md) — the
  protocol spec the coordinator implements. §6 "Network privacy"
  covers the threat model this transport setup mitigates.
- [scripts/cyncswap-dual-testnet-smoke.sh](../scripts/cyncswap-dual-testnet-smoke.sh) —
  the operator-driven dual-testnet smoke harness. Uses the plain-TCP
  transport for simplicity; can be adapted to Noise + Tor by
  swapping the constructor calls.
- [crates/coincync-swap/src/coordinator.rs](../crates/coincync-swap/src/coordinator.rs) —
  the source. `Coordinator` struct + 4 paired constructors at the top.
- Noise Protocol Framework: <https://noiseprotocol.org/noise.html>
- Tor hidden-service v3 spec: <https://spec.torproject.org/rend-spec/index.html>
