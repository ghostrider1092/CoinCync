# Disclaimer

CoinCync is software, not a product. There is no company. There is no support contract. There is no insurance. There is no recovery service. The maintainers cannot help you if you lose your wallet, your password, or your seed phrase. This page is the honest version of what you're getting and what you're not.

## What CoinCync is

- **Open-source software** under the MIT license, free to use, modify, and redistribute
- **A privacy cryptocurrency** with the cryptographic properties documented in [Privacy model](../protocol/privacy-model.md)
- **A network** that anyone can join by running a node and that no one controls
- **A constitution** of invariants ([Constitution](./constitution.md)) that the maintainers commit to never breaking

## What CoinCync is NOT

- **Not a regulated financial product**. CoinCync is not registered with the SEC, FinCEN, FCA, or any other financial regulator. It is not a security under the laws of any jurisdiction the maintainers are aware of, but **the maintainers are not lawyers and this is not legal advice**. Whether you can use CoinCync legally depends on where you live and what you do with it. Some jurisdictions have outright bans on privacy coins (China, Korea, India, Russia, others). Check your local law before using or holding CYNC.
- **Not insured**. There is no FDIC, no SIPC, no Lloyd's of London. If a bug in the code causes a loss, the maintainers have no obligation to compensate you and no money to do so even if they wanted to.
- **Not a managed service**. There is no customer support. There is no help desk. There is no recovery service for lost passwords or seed phrases. **If you lose your seed phrase AND your wallet password, your funds are unrecoverable. There is no exception, no special case, no backdoor.**
- **Not a stable store of value**. The price of CYNC against any other currency is determined by markets that may not exist yet, may be illiquid, may be manipulated, and may go to zero. The maintainers make no representation about future value.
- **Not audited** (yet). The cryptographic primitives (CLSAG, Bulletproofs+, RandomX) are individually well-studied and used by other privacy coins in production. The CoinCync-specific composition has been internally reviewed but **has not undergone an independent third-party audit as of this writing**. A bug in the composition could in principle be a privacy or correctness flaw.
- **Not future-proof**. Cryptography ages. Quantum computing advances. The CoinCync stack is built on elliptic-curve assumptions that may not hold in 30 years. Like every cryptocurrency in existence, the long-term security depends on the underlying primitives remaining unbroken.

## Risks you accept by using CoinCync

By running the binary, holding CYNC, or transacting on the network, you accept these risks (this list is not exhaustive):

1. **Loss of funds** through:
    - Lost seed phrase + lost password
    - Software bugs in the wallet, the node, or the cryptographic primitives
    - Hardware failure of a device storing the wallet file
    - Compromised dependencies (the Rust crates the project depends on)
    - User error (sending to the wrong address, losing the encrypted wallet file)
2. **Privacy compromise** through:
    - Network-layer correlation (broadcasting from your home IP)
    - Out-of-band metadata leakage (telling someone what you sent)
    - Chainalysis-style scraping of public infrastructure
    - Future cryptographic advances that weaken the current primitives
    - Operational mistakes (running a non-vendored explorer, leaking your view key)
3. **Legal risk** through:
    - Jurisdictions that ban privacy coins
    - Tax authorities that treat CYNC as taxable income or capital gains
    - Sanctions regimes that restrict transacting with certain addresses
    - Your own conduct (CoinCync is privacy-preserving, not consequence-preserving — what you do with it is on you)
4. **Network risk** through:
    - 51% attacks on the proof-of-work
    - Long-range attacks during initial sync
    - Eclipse attacks on individual nodes
    - Sybil attacks on the peer discovery
    - Bugs in the consensus rules that cause forks
5. **Project risk** through:
    - The maintainers losing interest, moving on, or being unable to continue
    - The project being co-opted, forked, or pressured by external parties
    - Compromise of the GitHub repository or the release signing keys

## What you should do

- **Read the source.** It's MIT licensed and available at [github.com/CyncDevelopment/Cync-Protocol](https://github.com/CyncDevelopment/Cync-Protocol). Don't run cryptocurrency software you haven't reviewed.
- **Run your own node.** Don't trust public infrastructure for anything you can't lose. Public explorers, public APIs, and public faucets are conveniences — they are not the source of truth.
- **Back up your seed phrase on paper.** Two copies, two locations, at least one fireproof. The seed phrase is the only thing that can recover funds; the encrypted wallet file alone is not enough if you forget the password.
- **Use a password long enough that an offline attacker can't brute-force it** even if they get the encrypted wallet file. The Argon2id KDF makes guessing expensive but not impossible — pick a password you wouldn't be embarrassed to write on paper.
- **Don't transact at scale until you've confirmed everything works at small scale.** The first transaction you send is not the time to find out the wallet is misconfigured.
- **Keep a copy of the binary you trust.** Future maintainers may release updates that you don't trust; the old binary is still valid software. Pin it.
- **Understand what you're using before you depend on it.** This is a hand-rolled privacy coin. It is not Bitcoin and it is not Monero. The risk profile is different. The audit history is shorter. The maintainer base is smaller.

## Maintainer commitments

The maintainers commit to:

- **Never adding a backdoor**, no matter who asks
- **Never adding a remote upgrade mechanism**
- **Never adding an operator key** that can override consensus
- **Never violating the constitution** (and rejecting any pull request that does)
- **Publishing the source for every release**
- **Documenting known issues honestly**, not burying them

The maintainers explicitly do NOT commit to:

- **Continuing to maintain the project indefinitely.** If the maintainers stop, the source is still there; anyone can fork it and continue.
- **Rapid response to bug reports.** This is a part-time project run by volunteers.
- **Any specific release schedule.**
- **Compensating users for any loss arising from the use of this software.**

## License

CoinCync is licensed under the MIT License. The full text is in [`LICENSE`](https://github.com/CyncDevelopment/Cync-Protocol/blob/main/LICENSE) at the repository root. The relevant clause:

> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

That's the legal version. The plain-English version: **you're using this at your own risk, and if it breaks, you keep both pieces.**

## See also

- [Constitution](./constitution.md) — the rules the maintainers commit to never breaking
- [`SECURITY.md`](https://github.com/CyncDevelopment/Cync-Protocol/blob/main/SECURITY.md) at the repository root — the responsible-disclosure process for security issues
