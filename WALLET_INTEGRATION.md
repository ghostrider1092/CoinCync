# CoinCync Wallet Integration Guide

**For wallet app developers (Trust Wallet, Exodus, Cake Wallet, custom apps)**

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

Returns current chain state for sync status display.

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
    "ring_size": 11,
    "network": "testnet"
  }
}
```

### 3. Scan for Outputs (Core Operation)

Scan the chain for outputs belonging to a wallet. Send the wallet's view and spend PUBLIC keys. The server scans blocks and returns matching outputs.

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
    "outputs": [
      {
        "tx_hash": "2cae3e22f520812b...",
        "output_index": 0,
        "height": 100,
        "stealth_address": "a1b2c3d4...",
        "commitment": "e5f6a7b8...",
        "encrypted_amount": "c9d0e1f2...",
        "tx_public_key": "1234abcd..."
      }
    ]
  }
}
```

**Privacy note:** The server learns which outputs belong to this view key. It does NOT learn the amounts (they're encrypted). For maximum privacy, run your own node.

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

### 7. Get Decoys

Get random outputs for building ring signatures. The wallet needs these to construct a valid CLSAG ring.

```json
// Request
{"jsonrpc":"2.0","method":"get_decoys","params":[88, 0],"id":1}

// Response
{
  "result": {
    "decoys": [
      {
        "public_key": "a1b2c3...",
        "commitment": "d4e5f6...",
        "height": 42
      }
    ]
  }
}
```

---

## Transaction Building Flow

Wallet apps must build and sign transactions **client-side**. The server never sees the spend key.

```
1. wallet_get_chain_info()     → get current height + fee rate
2. wallet_scan()               → find wallet's unspent outputs
3. get_decoys()                → get ring members for CLSAG
4. [CLIENT] select inputs      → choose UTXOs that cover amount + fee
5. [CLIENT] build transaction  → create outputs, compute commitments
6. [CLIENT] sign CLSAG         → sign each input with ring signature
7. [CLIENT] create BP+ proof   → generate Bulletproofs+ range proof
8. wallet_submit_tx()          → broadcast signed transaction
```

Steps 4-7 happen entirely on the client device. The server only provides chain data (step 1-3) and broadcasts the result (step 8).

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
2. **View key disclosure:** Sending the view PUBLIC key to the light wallet server reveals which outputs belong to the user. This is the privacy tradeoff. For maximum privacy, users should run their own node.
3. **Verify proofs:** After scanning, verify Bulletproofs+ range proofs on received outputs before trusting the amounts.
4. **Use fresh stealth addresses:** Every receive must use a unique one-time stealth address. Never reuse addresses.
5. **Uniform ring size:** All transactions must use exactly 11 ring members (MIN_RING_SIZE). Smaller rings are rejected by consensus.

---

## Testnet Resources

- **Explorer:** https://explorer.coincync.network
- **Faucet:** https://explorer.coincync.network (embedded, click "Faucet" tab)
- **RPC endpoint:** Any node on port 28081
- **Seed nodes:** 45.55.32.13, 165.245.161.62, 143.110.218.99, 165.245.140.113, 64.227.49.44, 138.68.172.80

---

## Contact

- GitHub: https://github.com/CyncDevelopment/Cync-Protocol
