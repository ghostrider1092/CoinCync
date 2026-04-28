# Create a wallet

The `coincync-wallet` binary creates encrypted on-disk wallets, derives addresses, signs transactions, and (when pointed at a running node) scans the chain for incoming payments.

## Generate a new wallet

```bash
./target/release/coincync-wallet --network testnet create
```

You'll be prompted for:

1. **A wallet password** (used to AEAD-encrypt the seed on disk via Argon2id + XChaCha20-Poly1305). Pick something long.
2. **Confirmation** of the password.

The command prints a **24-word BIP39 mnemonic phrase**. Write it down on paper. Keep the paper somewhere you can find it but a stranger cannot. The mnemonic is the only way to recover the wallet if the encrypted file is lost. If both the file and the mnemonic are lost, the funds are unrecoverable — **there is no customer support, no recovery service, no backdoor**.

The wallet file lands at `~/.coincync/wallets/default.wallet` by default. Override with `--wallet-file <path>`.

## Restore a wallet from a seed phrase

```bash
./target/release/coincync-wallet --network testnet restore
```

Prompts for the mnemonic phrase, then a new password to encrypt the restored wallet on disk. Produces an identical wallet to the one the mnemonic was originally generated for — same addresses, same view keys, same scan position.

## Show your address

```bash
./target/release/coincync-wallet --network testnet address
```

Prints the primary stealth address. This is what you give to a sender. Every transaction to this address generates a fresh one-time output that only you (with your view key) can detect; observers cannot link multiple payments to the same address — that's the whole point of stealth addressing.

## Check the balance

```bash
./target/release/coincync-wallet --network testnet balance
```

To know your balance, the wallet has to scan the chain for outputs addressed to you. The first scan from a fresh wallet on a synced testnet node takes a few minutes — every block since the wallet's `scanned_height` is fetched, every output is tested against your view key, and matches are decrypted to recover the amount.

Subsequent scans are incremental — only blocks since the last scan are checked.

## Get testnet CYNC from the faucet

```bash
# Visit https://faucet.coincync.network in a browser
# OR via the API:
curl -sX POST https://faucet.coincync.network/api/drip \
     -H 'content-type: application/json' \
     -d '{"address":"<your stealth address>"}'
```

The faucet sends a fixed amount (typically 10 CYNC) per address per cooldown window (24 hours). Wait a few seconds, then re-run `balance` and you should see the funds.

## Send a payment

```bash
./target/release/coincync-wallet --network testnet send \
     --to <recipient stealth address> \
     --amount 1.5
```

The wallet:

1. Selects your unspent outputs (UTXOs) that sum to ≥ amount + fee
2. Picks a ring of decoys from the chain's anonymity set
3. Constructs a CLSAG ring signature
4. Generates a Bulletproofs+ range proof for each output
5. Computes the canonical `signing_hash` (single source of truth — see [Transaction format](../protocol/transaction-format.md))
6. Submits the transaction to the local node's mempool via `send_raw_transaction`
7. Returns the transaction hash

The transaction propagates through the P2P network and is mined into a block within ~2 minutes (testnet inherits mainnet's 120-second target block time). Once it's in a block, the recipient's wallet detects it on its next scan.

## Show the seed phrase (with password)

```bash
./target/release/coincync-wallet --network testnet show-seed
```

Prompts for the wallet password, then prints the mnemonic. Use this for backup. **Don't run it on a screenshare or in a recorded terminal session.**

## Wallet security checklist

- [ ] **Mnemonic written down on paper**, stored somewhere physically secure
- [ ] **Wallet file backed up** to an offline medium (not a cloud sync)
- [ ] **Wallet password is long enough** that even a compromised file is uncrackable in any reasonable time. The Argon2id KDF with default parameters resists offline attack at ~1 hash/second on commodity hardware
- [ ] **No screenshare, no terminal recording** when running `show-seed`
- [ ] **Don't store the wallet file on a machine where untrusted code runs** (browsers, IM clients, etc.) — the file is encrypted but a keylogger captures the password as you type it

For the threat model behind these recommendations, see [Operations → Security](../operations/deployment.md).

## Next steps

- [Privacy model](../protocol/privacy-model.md) — what the cryptographic primitives actually protect against
- [JSON-RPC reference](../api/json-rpc.md) — call the node's API directly without the wallet binary
