# CoinCync Wallet Integration Guide

**For wallet app developers (Trust Wallet, Exodus, Cake Wallet, custom apps)**

CoinCync's promise: **privacy money that requires no permission.** Wallet integrations are evaluated against whether they keep that promise — in particular, against the constitutional posture (no KYC integration, no custodial fallback paths, no address blacklists). See [docs/explicitly-not-doing.md](docs/explicitly-not-doing.md) for the canonical list.

If your wallet is privacy-first and non-custodial, we want to support you. If you're looking for a coin to add to a regulated/KYC product, CoinCync is the wrong coin — that's by design, not oversight.

---

## Coin Specification

```json
{
  "ticker": "CYNC",
  "name": "CoinCync",
  "decimals": 12,
  "address_prefix": "tCYNC",
  "default_ring_size": 11,
  "default_rpc_port": 28081,
  "default_p2p_port": 28080,
  "block_time_seconds": 120,
  "supply_cap": "100000000",
  "privacy_model": "mandatory",
  "signature_scheme": "CLSAG",
  "range_proof": "Bulletproofs+",
  "address_type": "stealth",
  "fee_model": "per_byte_dynamic",
  "explorer_url": "https://explorer.coincync.network"
}
```

`default_ring_size` is bootstrap metadata for compatibility, not a transaction-building rule. The effective ring size is height-dependent; integrators must use the value returned by `wallet_get_chain_info` for the next block rather than hardcoding 11 or any other value.

**Key difference from other coins:** CoinCync is a mandatory-privacy coin. There are no transparent addresses, no public balances, no address-based lookups. All amounts are encrypted. All addresses are one-time stealth addresses.

---

## Light Wallet Server API

Base URL: `https://lightwallet.coincync.network` (or any node running the RPC server on port 28081)

All methods use JSON-RPC 2.0 over HTTP POST.

### 1. Get Coin Info

Returns the coin specification for your wallet UI.

```json
// Request
{"jsonrpc":"2.0","method":"wallet_get_coin_info","params":[],"id":1}

// Response
{
  "result": {
    "ticker": "CYNC",
    "name": "CoinCync",
    "decimals": 12,
    "address_prefix": "tCYNC",
    "default_ring_size": 11,
    "supply_cap": "100000000",
    "privacy_model": "mandatory",
    "signature_scheme": "CLSAG",
    "range_proof": "Bulletproofs+",
    "explorer_url": "https://explorer.coincync.network"
  }
}
```

### 2. Get Chain Info

Returns current chain state for sync status display and the ring size required for a transaction targeting the next block.

```json
// Request
{"jsonrpc":"2.0","method":"wallet_get_chain_info","params":[],"id":1}

// Response
{
  "result": {
    "height": 532,
    "synced": true,
    "difficulty": "4762",
    "block_time_target": 120,
    "min_fee_per_byte": 1000,
    "ring_size": 16,
    "network": "testnet"
  }
}
```

### 3. Scan for Outputs (Core Operation)

Scan the chain for candidate outputs belonging to a wallet. Send the wallet's view and spend PUBLIC keys. The current public scan endpoint returns candidates and sets `ownership_verified: false`; the client must perform ECDH/view-tag ownership verification itself before balance or spend decisions.

```json
// Request
{
  "jsonrpc": "2.0",
  "method": "wallet_scan",
  "params": {
    "view_public": "8c5d58a15ce37c970cdd2ba19f9d7a041691b5d176c011922dbf77c5bfb69a44",
    "spend_public": "ea1cdf29334bceb8469bd0ad9018e906e72f135c9ead9673a9459e696b324143",
    "start_height": 0,
    "max_blocks": 1000
  },
  "id": 1
}

// Response
{
  "result": {
    "blocks_scanned": 532,
    "scanned_to_height": 532,
    "chain_height": 532,
    "has_more": false,
    "ownership_verified": false,
    "outputs": [
      {
        "tx_hash": "2cae3e22f520812b...",
        "output_index": 0,
        "height": 100,
        "stealth_address": "a1b2c3d4...",
        "commitment": "e5f6a7b8...",
        "encrypted_amount": "c9d0e1f2...",
        "tx_public_key": "1234abcd...",
        "ownership_verified": false
      }
    ]
  }
}
```

A spend-capable wallet must also persist each owned output's canonical locator `(height, ordinal)`. The ordinal is the position of `(tx_hash, output_index)` in sorted canonical order for that block. Compute it while scanning full block/digest output data. Do not reveal an owned output through a separate lookup merely to recover its locator. Old sidecars without locators may be loaded, but must require a full rescan before spending.

**Privacy note:** The server learns which candidate query belongs to this client and can correlate request timing. It does NOT learn amounts. For maximum privacy, run your own node and scan locally.

### 4. Submit Transaction

Submit a signed transaction built by the wallet client.

```json
// Request
{"jsonrpc":"2.0","method":"wallet_submit_tx","params":["<hex-encoded-signed-tx>"],"id":1}

// Response (success)
{"result": {"accepted": true, "tx_hash": "ab12cd34..."}}

// Response (rejected)
{"error": {"code": -32000, "message": "rejected: fee too low"}}
```

### 5. Get Output Digests

Get compact output data for client-side scanning (if the wallet wants to scan locally instead of sending keys to the server).

```json
// Request
{"jsonrpc":"2.0","method":"wallet_get_digests","params":[0, 100],"id":1}

// Response
{
  "result": {
    "count": 100,
    "digests": [
      {
        "height": 0,
        "hash": "16b622021e712e18...",
        "output_count": 1,
        "timestamp": 1772784001
      }
    ]
  }
}
```

### 6. Estimate Fee

Estimate the fee for a transaction of a given size.

```json
// Request
{"jsonrpc":"2.0","method":"wallet_estimate_fee","params":[2400],"id":1}

// Response
{
  "result": {
    "estimated_fee": 2880000,
    "fee_per_byte": 1000,
    "tx_size": 2400
  }
}
```

### 7. Snapshot-Bound Output Locator RPCs

The node must not choose a wallet's decoys. The wallet first obtains output counts, samples locators locally, mixes every real input locator into one covered request, and resolves that request exactly once.

```json
// Distribution request
{"jsonrpc":"2.0","method":"get_decoy_distribution","params":[],"id":1}

// Distribution response
{
  "result": {
    "snapshot_height": 532,
    "snapshot_hash": "16b622021e712e18...",
    "policy_version": 1,
    "heights": [
      {"height": 0, "count": 1},
      {"height": 1, "count": 3}
    ]
  }
}
```

After selecting inputs and constructing one shuffled, duplicate-free covered locator set (128 entries in the reference wallet), resolve it with the same snapshot metadata:

```json
// Resolution request
{
  "jsonrpc": "2.0",
  "method": "get_outputs_by_locators",
  "params": [
    532,
    "16b622021e712e18...",
    1,
    [
      {"height": 100, "ordinal": 0},
      {"height": 220, "ordinal": 4}
    ]
  ],
  "id": 1
}

// Resolution response
{
  "result": {
    "snapshot_height": 532,
    "snapshot_hash": "16b622021e712e18...",
    "policy_version": 1,
    "outputs": [
      {
        "locator": {"height": 100, "ordinal": 0},
        "public_key": "a1b2c3...",
        "commitment": "d4e5f6...",
        "height": 100,
        "is_coinbase": false,
        "lock_height": null
      }
    ]
  }
}
```

The resolver accepts at most 256 locators. It rejects duplicate, missing, out-of-range, unknown-policy, or stale-snapshot requests as a whole and preserves request order on success. The wallet must validate metadata, cardinality, order, real-output identity, maturity, and lock state before allocating transaction-wide unique decoys.

`get_decoys` is deprecated and absent from the public REST allowlist. Do not retry with it, issue a second covered lookup, or fall back to a partial response.

---

## Transaction Building Flow

Wallet apps must build and sign transactions **client-side**. The server never sees the spend key.

```
1. wallet_get_chain_info()       → next-block height, fee rate, ring size
2. wallet_scan()/digest scan     → find and verify owned outputs; persist locators
3. [CLIENT] select inputs        → choose UTXOs that cover amount + fee
4. get_decoy_distribution()      → obtain snapshot-bound height counts
5. [CLIENT] sample locators      → log-gamma sampling; add all real locators
6. get_outputs_by_locators()     → exactly one shuffled covered lookup
7. [CLIENT] validate response    → metadata, order, identity, maturity, locks
8. [CLIENT] allocate rings       → no decoy reuse across transaction inputs
9. [CLIENT] build + sign         → outputs, commitments, CLSAG, Bulletproofs+
10. wallet_submit_tx()           → broadcast signed transaction
```

Steps 3, 5, and 7-9 happen entirely on the client device. Any stale snapshot, missing locator, malformed response, or insufficient eligible pool aborts the attempt without a second locator lookup.

---

## Address Format

CoinCync addresses encode two public keys (spend + view) in a single string:

```
tCYNC3ZMbzdXVYbvgCvWFFtEHo6uApWw5Ut1TDdgUg1koDAJ54hVoZnejEUgdUmqBVnfSnapWEfh8mihYGWH3tegUfAG1PFsHrvU
```

- Prefix: `tCYNC` (testnet) or `CYNC` (mainnet)
- Encoding: Base58Check
- Payload: `[network_byte][spend_pubkey_32][view_pubkey_32][checksum_4]`
- Total: 69 bytes encoded

---

## Key Derivation

CoinCync uses BIP39 (24-word mnemonic) for seed generation:

```
mnemonic → BIP39 seed (512 bits)
         → spend_secret (ed25519 scalar)
         → view_secret  = H(spend_secret)
         → spend_public = spend_secret * G
         → view_public  = view_secret * G
```

Curve: Ristretto255 (prime-order group on Curve25519)

---

## Security Requirements for Wallet Integrators

1. **NEVER send the spend secret key to any server.** Transaction signing must happen client-side.
2. **View-key disclosure:** A service that receives wallet-specific scan material can correlate the user with candidate outputs. For maximum privacy, users should run their own node and scan locally.
3. **Verify ownership and proofs:** Candidate scan results are not ownership proof. Perform ECDH/view-tag verification and verify Bulletproofs+ before trusting an amount.
4. **Persist canonical locators:** Every spendable owned output needs `(height, ordinal)`. Missing locators require a full rescan; never recover a real locator with an identifying one-off query.
5. **Use the height-aware ring size:** Read the next-block ring size from chain info and follow consensus activation rules. Do not hardcode the bootstrap minimum.
6. **One covered lookup:** Include every real locator, resolve one snapshot-bound set, allocate without transaction-wide decoy reuse, and fail closed without legacy fallback.

---

## Testnet Resources

- **Explorer:** https://explorer.coincync.network
- **Faucet:** https://explorer.coincync.network (embedded, click "Faucet" tab)
- **RPC endpoint:** Any node on port 28081
- **Seed nodes:** 66.135.23.193 (NYC), 140.82.57.168 (Amsterdam), 207.148.111.76 (Tokyo), 207.148.6.50 (Dallas), 95.179.165.225 (Frankfurt)

---

## Contact

- GitHub: https://git.coincync.network/coincync/cync-protocol
