# Transaction format

The on-the-wire and on-disk encoding of a CoinCync transaction. Defined by `src/transaction/types.rs`. The hash that gets signed (the "signing hash") is computed by a single canonical helper that both the wallet's signer and the consensus verifier funnel through — there is no second copy of the preimage logic.

## Struct

```rust
pub struct Transaction {
    pub version:     u8,
    pub tx_type:     TxType,    // Coinbase | Transfer | Churn
    pub inputs:      Vec<TxInput>,
    pub outputs:     Vec<TxOutput>,
    pub fee:         Amount,
    pub range_proof: Vec<u8>,
    pub extra:       Vec<u8>,
}

pub struct TxInput {
    pub key_image:                 KeyImage,                // CLSAG: I = x · H_p(x·G)
    pub ring_members:              Vec<RingMemberRef>,      // decoys + the real input
    pub signature:                 ClsagSignature,
    pub pseudo_output_commitment:  [u8; 32],                // for the balance equation
}

pub struct TxOutput {
    pub stealth_address:  PublicKey,
    pub tx_public_key:    PublicKey,
    pub commitment:       [u8; 32],     // Pedersen commitment to the amount
    pub encrypted_amount: Vec<u8>,      // ECDH-encrypted, recipient-only
    pub view_tag:         u8,           // 1-byte filter — wallet rejects 255/256 outputs without doing ECDH
    pub lock_height:      Option<u64>,  // optional time lock
    pub encrypted_memo:   Vec<u8>,      // optional ECDH-encrypted memo (≤ 256 bytes)
}
```

Borsh is the canonical serialization format. JSON encoding (used in the RPC layer) is a non-canonical view that's never hashed.

## The signing hash

The CLSAG ring signature is computed over a hash of every transaction field *except* the ring signatures themselves. This is the "signing hash" — the message that CLSAG binds to.

A bug in the signing-hash construction is a sign/verify mismatch: the wallet produces signatures the verifier rejects (best case) or the wallet produces signatures that validate against a different transaction (worst case — malleability vulnerability).

CoinCync prevents this category of bug by routing **both** the signer and the verifier through the same helper:

```rust
impl Transaction {
    pub fn signing_hash(&self) -> Hash {
        Self::compute_signing_hash(
            self.version, self.tx_type, self.fee,
            self.inputs.iter().map(SigningInputView::from_txinput),
            &self.outputs, &self.range_proof, &self.extra,
        )
    }

    /// Single source of truth for the CLSAG signing message.
    pub fn compute_signing_hash<'a, I>(
        version: u8, tx_type: TxType, fee: Amount,
        inputs: I, outputs: &[TxOutput],
        range_proof: &[u8], extra: &[u8],
    ) -> Hash
    where I: IntoIterator<Item = SigningInputView<'a>>
    { /* ... */ }
}
```

`SigningInputView` is a light view over the fields of a `TxInput` *except* the signature, so the builder can compute the signing hash before any CLSAG signature exists. The `tests/wallet_roundtrip.rs::signing_hash_is_single_source_of_truth` integration test pins the two paths together — any future drift fails CI.

## Preimage layout

Every byte that goes into the signing hash, in order:

```text
domain tag:  "coincync/tx-sign/v1"          (19 bytes, ASCII, no length prefix)
version:     u8                             (1 byte)
tx_type:     u8                             (1 byte)
fee:         u64 little-endian              (8 bytes)
n_inputs:    u32 little-endian              (4 bytes)
for each input:
    key_image:                32 bytes
    pseudo_output_commitment: 32 bytes
    n_ring_members:           u32 LE
    for each ring member:
        public_key:           32 bytes
        commitment:           32 bytes
n_outputs:   u32 little-endian              (4 bytes)
for each output:
    stealth_address:          32 bytes
    tx_public_key:            32 bytes
    commitment:               32 bytes
    encrypted_amount.len():   u32 LE
    encrypted_amount:         (var)
    view_tag:                 u8
    lock_height tag:          u8 (0 = None, 1 = Some)
    if Some(h):
        h:                    u64 LE
    encrypted_memo.len():     u32 LE
    encrypted_memo:           (var)
range_proof.len():            u32 LE
range_proof:                  (var)
extra.len():                  u32 LE
extra:                        (var)
```

Then `BLAKE3` over the whole concatenated buffer.

### Why every variable-length field is length-prefixed

Without the length prefixes, an attacker could craft two transactions that serialize to the same bytes by reshuffling input/output counts and content — a classic prefix-collision vulnerability. The `u32` length prefix on every variable-length field (and the explicit `n_inputs` / `n_outputs` counts before each loop) makes that impossible.

### Why `lock_height` uses an explicit tag

`lock_height: Option<u64>` could be encoded as just the `u64` with `0` meaning "no lock," but then `Some(0)` and `None` would be indistinguishable. The explicit `u8` tag (0 for `None`, 1 for `Some`) keeps them distinct.

### Why the domain tag

`coincync/tx-sign/v1` is the domain-separation tag. Every hash preimage in the protocol uses a different tag, so two hashes computed with different tags can never collide regardless of the underlying bytes. This eliminates a class of cross-protocol attacks where an adversary tries to make a CLSAG message also be a valid block header hash, or similar. See [Privacy model → Hash domain separation](./privacy-model.md#hash-domain-separation).

## The transaction hash

`Transaction::hash()` is **different** from `signing_hash()`. The transaction hash includes the signatures (it's borsh-of-the-whole-transaction blake3'd) and is what gets used as the txid for mempool lookup, block inclusion, and explorer references. The signing hash is purely the CLSAG message.

## What's in `extra`

The `extra` field is a free-form byte buffer included in the signing hash. It's typically empty for normal transactions. Coinbase transactions store the genesis message in here for the genesis block (`"CoinCync Mainnet Genesis - Privacy You Can Audit - October 2026"`).

The protocol does not assign meaning to `extra` for non-coinbase transactions. Wallets that want to embed protocol-level annotations (multi-tx batching IDs, payment IDs, etc.) can do so here, but they should be aware that:

- The bytes are visible in the on-chain transaction (they're length-prefixed in the signing hash but not encrypted)
- Anything in `extra` is potentially a deanonymization side-channel — a wallet that tags transactions with patterns identifies its users to a chain analyst
- The recommended posture is "leave it empty unless you have a specific protocol need"

## Wire size

Approximate transaction size as a function of ring size and output count:

| Ring size | 1 input → 2 outputs | 1 input → 4 outputs |
|---|---|---|
| 11 (current minimum) | ~2.1 KB | ~3.5 KB |
| 16 (CIP-002 future) | ~2.6 KB | ~4.0 KB |

Most of the bulk is the range proof (~700 bytes for 2 outputs with Bulletproofs+, ~1400 bytes for 4 outputs).

## See also

- `src/transaction/types.rs` — the canonical struct and the signing-hash helper
- `src/transaction/builder.rs` — the wallet-side `TransactionBuilder` that funnels through `compute_signing_hash`
- `src/consensus/validation.rs::validate_transaction` — the verifier-side check
- [Privacy model](./privacy-model.md) — the cryptographic primitives that protect each field
