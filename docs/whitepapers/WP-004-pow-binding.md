# WP-004 · Proof-of-Work Binding
### The block anchor, genesis-bound RandomX epochs, and a claim we withdrew

**Status:** Shipped · **Layer:** Consensus · **Series:** [CoinCync Whitepapers](README.md)

---

## 1. Motivation

Proof-of-work is only meaningful if the work is **bound to the thing it claims to
secure**. Work computed over a value that does not commit to the parent block can
be replayed on a fork. Work computed over a value that does not commit to the
transaction set can be reused after swapping the transactions. Work computed with
a key another network also uses is work that transfers between chains.

CoinCync is CPU-only by constitution: RandomX, no ASIC path, no merge-mining. That
raises the stakes on binding, because the whole security argument rests on work
being expensive *and* non-transferable.

---

## 2. Threat addressed

| Attack | Assumption it needs | What we removed |
|---|---|---|
| **Work replay onto a different parent** | The PoW input does not commit to the parent | The anchor mixes `prev_hash` in twice — into the seed and into the final mix |
| **Transaction substitution after mining** | PoW commits to a header that does not fix the tx set | The hash is taken over `(anchor ‖ nonce ‖ tx_root)` |
| **Cross-network work transfer** — mainnet work counted on testnet or vice versa | The RandomX VM key is network-independent | Epoch keys are derived from the **network's genesis hash** |
| **ASIC / GPU advantage** | The algorithm is amenable to specialised hardware | RandomX, CPU-only, enforced at build time |
| **Silent miner death on Windows** — the process vanishes mid-loop, no error | JIT code pages stay executable | `FLAG_SECURE` (W^X) on Windows |

---

## 3. Design

### 3.1 The anchor

Each block's PoW input is derived through a fixed chain:

```
seed       = H(prev_hash ‖ height ‖ timestamp)
sequential = SEQ_PAD_ITER^n(seed)              (n = SEQ_PAD_ITERATIONS)
anchor     = H_domain("CYNC1_ANCHOR_MIX", sequential ‖ prev_hash)
pow_hash   = RandomX_key(height) ( anchor ‖ nonce ‖ tx_root )
```

Three bindings follow:

- **Parent** — `prev_hash` enters both the seed and the final mix. Work is
  valid only at one point on one chain.
- **Position and time** — `height` and `timestamp` are in the seed, so the same
  parent at a different height or timestamp is different work.
- **Contents** — `tx_root` is hashed with the nonce, so a miner cannot find a
  nonce and then swap the transaction set.

Every intermediate is deterministic from `(prev_hash, height, timestamp)`, so
anchors are cached in a FIFO-evicting map with O(1) lookup — a validator
re-checking many candidate nonces for one block computes the padding once.

### 3.2 The claim we withdrew — sequential padding is not a VDF

The iterated hash in §3.1 was originally presented as a sequential-delay
component. It is not, and the code now says so in as many words:

> Sequential padding — a hash chain that provides **no verifiable sequential
> delay property**. This is **NOT a VDF**. It merely binds the PoW anchor to the
> previous block via iterated hashing.

The distinction matters. A verifiable delay function proves that wall-clock time
passed and is *fast to verify*. An iterated hash proves neither: a verifier must
redo every iteration, and a parallel attacker with many cores gains nothing but
also loses nothing meaningful. The construction is a **binding** step, not a
timing one.

We record the withdrawal rather than quietly deleting the claim, because the
series' value depends on its claims being checkable — and a project that
overstates one primitive invites doubt about the rest. The padding still earns its
place: it makes the anchor depend on the parent through a fixed amount of work
that cannot be shortcut, which is what §3.1 needs from it.

### 3.3 Genesis-bound RandomX epoch keys

The RandomX VM key rotates every **2048 blocks** (`RANDOMX_KEY_EPOCH`) — roughly
2.8 days at 120-second blocks — and is derived as a domain-separated hash of the
epoch index **and the network's genesis hash**.

Binding to genesis makes work network-specific: testnet work is not mainnet work,
because the VM computing it is keyed differently. `bind_randomx_genesis_for_network`
is called once at process start by both `coincync-node` and `coincync-miner`,
before any PoW.

**The epoch length is a sync-performance decision, not a security one.** It was
raised from 64 to 2048 because every epoch boundary triggers a 0.5–1 s VM
reinitialisation, and during initial block download those reinitialisations
dominated the validation pipeline. Longer epochs mean faster sync. Since the key
is public and derived, a longer epoch does not weaken the PoW.

**A deployment failure this design fixed.** Before the explicit binding call,
the key derivation fell back to a `COINCYNC_NETWORK` environment variable that
defaults to **mainnet** — while `coincync-node` defaults to **testnet**. A node
and its peers would then compute different VM keys and every block would appear
to have "invalid PoW," with no indication of the real cause. The fallback path
still exists but now emits a loud, once-only error naming the exact remedy. This
is the general pattern: **a silent default that disagrees with another
component's default is a bug waiting for a confusing symptom.**

### 3.4 `FLAG_SECURE` on Windows — W^X

On Windows, RandomX's JIT allocates a code buffer that stays writable and
executable. Under Windows DEP and Defender exploit-protection, that buffer's
execute permission can be **revoked out from under the running program**. The
result is an access violation that kills the process with **no catchable Rust
error** — the miner simply vanishes mid-loop. It was observed intermittently in
light+JIT mode at block heights 66, 91, and 99.

`FLAG_SECURE` switches the JIT to the W^X pattern: the buffer is writable while
emitting, flipped to executable before it runs, and back to writable to
recompile. It is the reference library's remedy for exactly this failure. It
costs a few percent of hashrate on Windows; non-Windows platforms keep the fast
path (`FLAG_DEFAULT`, so the flag combination is a no-op there).

**This is consensus-safe**, and the reason is worth stating precisely: RandomX
guarantees **byte-identical hash output across every flag combination**. The
flags govern memory protection and performance, never the computed hash. The
property is covered by a `fast_light_equivalence` test rather than asserted. A
flag that changed the hash would be a chain split between operating systems.

Verified in practice: an unsupervised rig ran 153 blocks with zero crashes after
the change.

### 3.5 RandomX-only, enforced at build time

`PowAlgorithm` has a single variant. A build without the `randomx` feature cannot
verify proof-of-work at all, so `src/lib.rs` fails compilation with an explicit
message rather than producing a binary that silently accepts anything. Removing
the algorithm choice removes a class of consensus divergence and matches the
constitutional CPU-only commitment.

Runtime modes are a resource trade, not a consensus one: full mode needs ~2.5 GB
(256 MB cache + 2 GB dataset, shared across threads via refcount); light mode is
cache-only at ~256 MB and 5–10× slower per hash. Operators on low-RAM systems can
force light mode by environment variable. Both compute identical hashes.

---

## 4. Security analysis

**What holds.** Work is bound to parent, height, timestamp, and transaction set;
epoch keys are network-specific; the algorithm is fixed and CPU-only; flag
differences cannot cause a chain split.

**What this does not protect against.**

- **The padding is not a delay proof** (§3.2) — no timing guarantee is claimed.
- **51% attacks.** Binding makes work non-transferable; it does not make it
  unbuyable. Reorg defense is WP-005.
- **CPU-only is a policy, not a proof.** RandomX resists ASICs by design and has
  held up in practice, but "CPU-only" is a claim about current hardware
  economics.
- **A low-hashrate chain is cheap to attack** regardless of algorithm. That is a
  bootstrap risk mitigated operationally (WP-005, WP-008), not by PoW binding.
- **The genesis-fallback path still exists.** It logs loudly, but a misconfigured
  operator can still start a daemon that derives the wrong key. The robust fix
  would be to fail closed rather than warn.

---

## 5. Implementation

| Component | Location |
|---|---|
| Anchor, sequential padding, mix, anchor cache | `src/consensus/pow.rs` |
| `bind_randomx_genesis_for_network`, `randomx_key_for_height` | `src/consensus/pow.rs` |
| `RANDOMX_KEY_EPOCH`, VM/dataset sharing, light-mode fallback | `src/consensus/pow.rs` |
| `FLAG_SECURE` on Windows + `fast_light_equivalence` test | `src/consensus/pow.rs` |
| Build-time RandomX requirement | `src/lib.rs` |
| Genesis hashes | `src/mainnet.rs`, `src/testnet.rs` |

`src/consensus/pow.rs` is **hash-locked** (WP-007): editing it fails the build
until the lock is regenerated deliberately.

---

## 6. Known limits

- Sequential padding provides binding only; no timing property (§3.2).
- The wrong-genesis fallback warns rather than failing closed (§4).
- `FLAG_SECURE` costs a few percent of Windows hashrate.
- Full-mode memory (~2.5 GB) is a real barrier on small machines; light mode
  is 5–10× slower.
- Epoch length (2048) is tuned for sync throughput; it has not been re-derived
  against any adversarial model.

---

## 7. References

- tevador et al., *RandomX* specification and design rationale — including the
  flag-independence guarantee §3.4 relies on.
- Boneh et al. (2018) — verifiable delay functions, i.e. what §3.2 is *not*.
- Internal: [WP-001 Difficulty stability](WP-001-difficulty-stability.md),
  [WP-005 Reorg defense](WP-005-layered-reorg-defense.md),
  [WP-007 Hash lock](WP-007-critical-files-hash-lock.md),
  [WP-100](WP-100-solved-issues-ledger.md).
